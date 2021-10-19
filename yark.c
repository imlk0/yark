#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Students from Institute of Information Engineering");
MODULE_DESCRIPTION("Yet another rootkit.");
MODULE_VERSION("0.01");

static int __init yark_init(void) {
    printk(KERN_INFO "Hello world 1.\n");

    /*
     * A non 0 return means init_module failed; module can't be loaded.
     */
    return 0;
}

static void __exit yark_exit(void) { printk(KERN_INFO "Goodbye world 1.\n"); }

module_init(yark_init);
module_exit(yark_exit);