#include "yhook.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
unsigned long lookup_addr_by_name(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name};
    unsigned long retval;

    if (register_kprobe(&kp) < 0)
        return 0;
    retval = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return retval;
}
#else
unsigned long lookup_addr_by_name(const char *name)
{
    return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif



// Get the address of the hooked function by name
static int resolve_hook_address(struct ftrace_hook *hook)
{
    hook->orig_address = lookup_addr_by_name(hook->symbol_name);

    if (!hook->orig_address)
    {
        pr_debug("unresolved symbol: %s\n", hook->symbol_name);
        return -ENOENT;
    }

    *((unsigned long *)hook->orig_function) = hook->orig_address;
    return 0;
}

// Callback function of the tracked function
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs;
    struct ftrace_hook *hook;

    regs = ftrace_get_regs(fregs);
    hook = container_of(ops, struct ftrace_hook, ops); // Get the address of the "struct ftrace_hook"
    if (!within_module(parent_ip, THIS_MODULE))                            // Preventing the tracked function from being called recursively
    {
        regs->ip = (unsigned long)hook->hook_function; //set ip to hook function
    }
}

// register hook by ftrace
static int fh_install_hook(struct ftrace_hook *hook)
{
    int err;
    err = resolve_hook_address(hook);
    if (err)
        return err;
    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
    err = ftrace_set_filter_ip(&hook->ops, hook->orig_address, 0, 0);
    if (err)
    {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err)
    {
        pr_debug("register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->orig_address, 1, 0);

        return err;
    }

    return 0;
}

//unregister a hook
static void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err)
    {
        pr_debug("unregister_ftrace_function() failed: %d\n", err);
    }
    err = ftrace_set_filter_ip(&hook->ops, hook->orig_address, 1, 0);
    if (err)
    {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
    }
}


DECLARE_HASHTABLE(hook_function_list, HOOK_FUNCTION_HASH_TABLE_BITS);


static u32 hook_function_name_hash(const char* fn_name) {
    /* TODO */
    u32 i = (u32)(*fn_name);
    return i;
}

int hook_function_name_add(const char* fn_name,void *hook_fn,void *orig_fn) {
    struct hook_function_info *cur;
    struct hook_function_info *info;
    struct ftrace_hook *hooker;
    u32 hash;
    /* allocate for hooker */
    hooker = (struct ftrace_hook *)kmalloc(sizeof(struct ftrace_hook),GFP_KERNEL);
    if (!hooker)
        return -ENOMEM;
    hooker->symbol_name = fn_name;
    hooker->hook_function = hook_fn;
    hooker->orig_function = orig_fn;
    hash = hook_function_name_hash(fn_name);

    /* check if the function is already hook */
    hash_for_each_possible(hook_function_list, cur, node, hash) {
        if (!strcmp(cur->hook_function_name,fn_name))
            return 0;
    }
    /* allocate for store hook function info */
    info = (struct hook_function_info *)kmalloc(sizeof(struct hook_function_info),
                                            GFP_KERNEL);
    if (!info)
        return -ENOMEM;
    info->hook_function_name = fn_name;
    info->fhooker = hooker;
    hash_add(hook_function_list, &info->node, hash);
    fh_install_hook(hooker);//err deal
    pr_info("add hook to %s\n",fn_name);
    return 0;
}

int hook_function_del(const char* fn_name) {
    struct hook_function_info *cur;
    u32 hash;

    hash = hook_function_name_hash(fn_name);
    hash_for_each_possible(hook_function_list, cur, node, hash) {
        if (!strcmp(cur->hook_function_name,fn_name)) {
            pr_info("del hook to %s\n",fn_name);
            hash_del(&cur->node);
            fh_remove_hook(cur->fhooker);
            kfree(cur->fhooker);
            kfree(cur);
            break;
        }
    }
    return 0;
}