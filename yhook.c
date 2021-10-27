#include "yhook.h"
#include "main.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *
ftrace_get_regs(struct ftrace_regs *fregs) {
    return fregs;
}
#endif

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static kallsyms_lookup_name_t kallsyms_lookup_name_ref;
static t_syscall *sys_call_table_ref;

/* lookup with kallsyms_lookup_name(), which is better register_kprobe() since
 * it can also find non-function symbols.
 */
unsigned long lookup_addr_by_name(const char *name) {
    if (!kallsyms_lookup_name_ref)
        return 0;
    return kallsyms_lookup_name_ref(name);
}

int yhook_init(void) {
    /* lookup address of kallsyms_lookup_name() */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
    if (register_kprobe(&kp) < 0)
        return -EFAULT;
    kallsyms_lookup_name_ref = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    if (!kallsyms_lookup_name_ref) {
        pr_err(LOG_PREFIX "failed to lookup function kallsyms_lookup_name()\n");
        return -EFAULT;
    }
#else
    kallsyms_lookup_name_ref = kallsyms_lookup_name;
#endif

    /* lookup address of sys_call_table */
    sys_call_table_ref =
        (t_syscall *)kallsyms_lookup_name_ref("sys_call_table");
    if (!sys_call_table_ref) {
        pr_err(LOG_PREFIX "failed to lookup symbol: sys_call_table\n");
        return -EFAULT;
    }
    return 0;
}

// Callback function of the tracked function
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs) {
    struct pt_regs *regs;
    struct ftrace_hook *hook;

    regs = ftrace_get_regs(fregs);
    /* Get the address of the "struct ftrace_hook" */
    hook = container_of(ops, struct ftrace_hook, ops);
    /* Preventing the tracked function from being called recursively */
    if (!within_module(parent_ip, THIS_MODULE)) {
        hook->orig_address = ip;
        *hook->orig_function = (void *)hook->orig_address;
        /* set ip to hook function */
        regs->ip = (unsigned long)hook->hook_function;
    }
}

// register hook by ftrace
static int fh_install_hook(struct ftrace_hook *hook) {
    int err;
    int symbol_name_len;
    char *symbol_name_owned;

    /* prepare struct ftrace_ops */
    hook->ops = (struct ftrace_ops){
        .func = fh_ftrace_thunk,
        .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
                 FTRACE_OPS_FL_IPMODIFY,
    };
    /* ftrace_set_filter() may modify the content of buf, so we make a copy of
     * hook->symbol_name for it */
    symbol_name_len = strlen(hook->symbol_name);
    symbol_name_owned = kmalloc(symbol_name_len + 1, GFP_KERNEL);
    memcpy(symbol_name_owned, hook->symbol_name, symbol_name_len);
    symbol_name_owned[symbol_name_len + 1] = '\0';
    /* call ftrace_set_filter() to search for target function */
    err = ftrace_set_filter(&hook->ops, symbol_name_owned,
                            strlen(hook->symbol_name), 0);
    kfree(symbol_name_owned);
    if (err) {
        pr_err("ftrace_set_filter() failed: %d symbol: %s\n", err,
                 hook->symbol_name);
        return err;
    }
    /* enable tracing call */
    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_err("register_ftrace_function() failed: %d\n", err);
        return err;
    }
    return 0;
}

// unregister a hook
static void fh_remove_hook(struct ftrace_hook *hook) {
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err)
        pr_err("unregister_ftrace_function() failed: %d\n", err);
}

static inline void write_cr0_forced(unsigned long val) {
    unsigned long __force_order;
    asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

void hook_sys_call_table(long int sysno, t_syscall hook_fn,
                         t_syscall *orig_fn) {
    unsigned long cr0;
    pr_info(LOG_PREFIX "hook syscall number %ld", sysno);
    if (!sys_call_table_ref) {
        pr_warn(LOG_PREFIX
                "address of sys_call_table was not found, skip hook\n");
        return;
    }
    cr0 = read_cr0();
    *orig_fn = sys_call_table_ref[sysno];
    write_cr0_forced(cr0 & ~0x00010000);
    sys_call_table_ref[sysno] = hook_fn;
    write_cr0_forced(cr0);
}

void unhook_sys_call_table(long int sysno, t_syscall orig_fn) {
    unsigned long cr0;
    pr_info(LOG_PREFIX "unhook syscall number %ld", sysno);
    if (!sys_call_table_ref) {
        pr_warn(LOG_PREFIX
                "address of sys_call_table was not found, skip unhook\n");
        return;
    }
    cr0 = read_cr0();
    write_cr0_forced(cr0 & ~0x00010000);
    sys_call_table_ref[sysno] = *orig_fn;
    write_cr0_forced(cr0);
}

DECLARE_HASHTABLE(hook_function_list, HOOK_FUNCTION_HASH_TABLE_BITS);

static u32 hook_function_name_hash(const char *fn_name) {
    /* TODO */
    u32 i = (u32)(*fn_name);
    return i;
}

int hook_function_name_add(const char *fn_name, void *hook_fn, void *orig_fn) {
    struct hook_function_info *cur;
    struct hook_function_info *info;
    struct ftrace_hook *hooker;
    u32 hash;
    int err;

    /* allocate for hooker */
    hooker =
        (struct ftrace_hook *)kmalloc(sizeof(struct ftrace_hook), GFP_KERNEL);
    if (!hooker)
        return -ENOMEM;
    hooker->symbol_name = fn_name;
    hooker->hook_function = hook_fn;
    hooker->orig_function = (void **)orig_fn;
    hash = hook_function_name_hash(fn_name);

    /* check if the function is already hook */
    hash_for_each_possible(hook_function_list, cur, node, hash) {
        if (!strcmp(cur->hook_function_name, fn_name))
            return 0;
    }
    /* allocate for store hook function info */
    info = (struct hook_function_info *)kmalloc(
        sizeof(struct hook_function_info), GFP_KERNEL);
    if (!info)
        return -ENOMEM;
    info->hook_function_name = fn_name;
    info->fhooker = hooker;
    hash_add(hook_function_list, &info->node, hash);
    err = fh_install_hook(hooker); // err deal
    pr_info(LOG_PREFIX "add hook to %s return: %d\n", fn_name, err);
    return err;
}

int hook_function_del(const char *fn_name) {
    struct hook_function_info *cur;
    u32 hash;

    hash = hook_function_name_hash(fn_name);
    hash_for_each_possible(hook_function_list, cur, node, hash) {
        if (!strcmp(cur->hook_function_name, fn_name)) {
            pr_info(LOG_PREFIX "del hook to %s\n", fn_name);
            hash_del(&cur->node);
            fh_remove_hook(cur->fhooker);
            kfree(cur->fhooker);
            kfree(cur);
            break;
        }
    }
    return 0;
}