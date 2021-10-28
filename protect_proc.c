#include <linux/version.h>
#include <linux/types.h>
#include "protect_proc.h"
#include "yhook.h"
#include "main.h"

LIST_HEAD(protect_proc_info_list);

static int protect_proccess(pid_t pid,int sig){
    if (sig == SIGKILL || sig == SIGTERM){
        struct protect_proc_info *pos;
        list_for_each_entry(pos,&protect_proc_info_list,list) {
            if (pos->pid == pid){
                pr_info(LOG_PREFIX "prevent user kill pid %d,QWQ...\n",pid);
                return 1;
            }
        }
    }
    return 0;
}

static asmlinkage long (*orig_sys_kill)(const struct pt_regs *);

asmlinkage long hook_sys_kill(const struct pt_regs *regs)
{
    pid_t pid = regs->di;
    int sig = regs->si;
    if (protect_proccess(pid,sig)){
        return 0;
    }
    return orig_sys_kill(regs);
}



int protect_proc_init() {
    pr_info(LOG_PREFIX "call protect_proc_init()\n");
    hook_sys_call_table(__NR_kill, hook_sys_kill, &orig_sys_kill);
    return 0;
}

int protect_proc_add(pid_t pid) {
    struct protect_proc_info *info,*pos;
    
    /* check if the pid is already protected */
    list_for_each_entry(pos,&protect_proc_info_list,list) {
       if (pos->pid == pid){
           pr_info(LOG_PREFIX "pid %d is already protected!\n",pid);
           return -ENOMEM;
       }
    }

    info = (struct protect_proc_info *)kmalloc(sizeof(struct protect_proc_info), GFP_KERNEL);
    info->pid = pid;
    INIT_LIST_HEAD(&(info->list));
    list_add(&(info->list), &protect_proc_info_list);
    pr_info(LOG_PREFIX "pid %d is protected...\n",pid);
    return 0;
}

int protect_proc_del(pid_t pid) {
    struct protect_proc_info *pos;
    int if_find;
    if_find = 0;

    list_for_each_entry(pos,&protect_proc_info_list,list) {
       if (pos->pid == pid){
           list_del(&(pos->list));
           kfree(pos);
           pr_info(LOG_PREFIX "pid %d is successfully unprotected...\n",pid);
           if_find = 1;
           break;
       }
    }
    if (if_find == 0){
        pr_info(LOG_PREFIX "no such pid %d\n",pid);
    }
    return 0;
}

int protect_proc_exit() {
    struct protect_proc_info *pos;
    pr_info(LOG_PREFIX "call protect_proc_exit()\n");
    unhook_sys_call_table(__NR_kill, orig_sys_kill);

    list_for_each_entry(pos,&protect_proc_info_list,list) {
        list_del(&(pos->list));
        kfree(pos);
        pr_info(LOG_PREFIX "pid %d is auto unprotected when yark exit...\n",pos->pid);
    }
    return 0;
}
