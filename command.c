#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include "command.h"
#include "main.h"

// TODO: Obfuscate the this path name at compile time:
#define SYS_DIR_NAME "yark"

static ssize_t myvariable_show(struct kobject *kobj,
                               struct kobj_attribute *attr, char *buf) {
    return 0;
}

static ssize_t myvariable_store(struct kobject *kobj,
                                struct kobj_attribute *attr, const char *buf,
                                size_t count) {
    return 0;
}

static struct kobject *module_kobj;

static struct kobj_attribute hide_file_kobj_list_attribute =
    __ATTR(list, 0400, myvariable_show, NULL);
static struct kobj_attribute hide_file_kobj_add_attribute =
    __ATTR(add, 0200, NULL, myvariable_store);
static struct kobj_attribute hide_file_kobj_del_attribute =
    __ATTR(del, 0200, NULL, myvariable_store);

static struct attribute *hide_file_attrs[] = {
    &hide_file_kobj_list_attribute.attr, &hide_file_kobj_add_attribute.attr,
    &hide_file_kobj_del_attribute.attr, NULL};

static struct attribute_group hide_file_attr_group = {
    .name = "hide_file",
    .attrs = hide_file_attrs,
};

int command_start(void) {
    int retval = 0;

    pr_info(LOG_PREFIX "call command_start()");

    // create /sys/kernel/${SYS_DIR_NAME}/
    module_kobj = kobject_create_and_add(SYS_DIR_NAME, kernel_kobj);
    if (!module_kobj)
        return -ENOMEM;
    // create /sys/kernel/${SYS_DIR_NAME}/hide_file/*
    retval = sysfs_create_group(module_kobj, &hide_file_attr_group);
    if (retval)
        kobject_put(module_kobj);

    return retval;
}

void command_end(void) {
    pr_info(LOG_PREFIX "call command_end()");
    kobject_put(module_kobj);
}
