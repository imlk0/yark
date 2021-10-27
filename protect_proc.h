#ifndef YARK_PROTECT_PROC_H
#define YARK_PROTECT_PROC_H

struct protect_proc_info {
    pid_t pid;
    struct list_head list;
};

int protect_proc_init(void);
int protect_proc_exit(void);
int protect_proc_add(int port);
int protect_proc_del(int port);

extern struct list_head protect_proc_info_list;

#endif