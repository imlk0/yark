#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#pragma GCC optimize("-fno-optimize-sibling-calls")//防止递归触发

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long lookup_addr_by_name(const char *name)
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
static unsigned long lookup_addr_by_name(const char *name)
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

/*
symbol_name: 被hook的函数名
hook_function: 钩子函数的地址(替代被hook函数)
orig_function: 被hook函数的地址的指针
orig_address:  被hook函数的地址
ops:      ftrace服务信息
*/
struct ftrace_hook
{
    const char *symbol_name;
    void *hook_function;
    void *orig_function;

    unsigned long orig_address;
    struct ftrace_ops ops;
};

// 注册hook函数时，只需要提供3个参数，被hook的函数符号名、用于替换原函数的hook函数指针、以及原函数指针。
#define YARK_HOOK(_symbol_name, _hook_function, _orig_function) \
    {                                                           \
        .symbol_name = (_symbol_name),                          \
        .hook_function = (_hook_function),                      \
        .orig_function = (_orig_function),                      \
    }

// 通过hook里的symbol_name字段获取到被hook函数的地址并写入结构体
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

// 被跟踪函数的回调函数
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs;
    struct ftrace_hook *hook;

    regs = ftrace_get_regs(fregs);
    hook = container_of(ops, struct ftrace_hook, ops); // 获得hook结构的首地址
    if (!within_module(parent_ip, THIS_MODULE))                            // 防止被跟踪函数被递归调用
    {
        regs->ip = (unsigned long)hook->hook_function; //将ip篡改为用户实现的hook函数的指针
    }
}

// 通过ftrace注册一个hook
int fh_install_hook(struct ftrace_hook *hook)
{
    int err;
    err = resolve_hook_address(hook);
    if (err)
        return err;
    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
    err = ftrace_set_filter_ip(&hook->ops, hook->orig_address, 0, 0); //只对被跟踪的函数进行ftrace
    if (err)
    {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops); // 注册
    if (err)
    {
        pr_debug("register_ftrace_function() failed: %d\n", err);
        //注册失败，关闭ftrace
        ftrace_set_filter_ip(&hook->ops, hook->orig_address, 1, 0);

        return err;
    }

    return 0;
}

//卸载一个hook
void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops); //取消注册
    if (err)
    {
        pr_debug("unregister_ftrace_function() failed: %d\n", err);
    }
    err = ftrace_set_filter_ip(&hook->ops, hook->orig_address, 1, 0); //取消跟踪
    if (err)
    {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
    }
}