#ifndef YARK_HIDE_PROC_H
#define YARK_HIDE_PROC_H


struct hide_proc_info {
    pid_t pid;
    struct hide_proc_info *next;
};

struct hide_proc_info *get_hide_proc_info_list_head(void);
int hide_proc_init(void);
int hide_proc_exit(void);
int hide_proc_add(pid_t pid);
int hide_proc_del(pid_t pid);

#endif