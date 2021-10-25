#ifndef YARK_HIDE_FILE_H
#define YARK_HIDE_FILE_H

#include <linux/dcache.h>
#include <linux/hashtable.h>
#include <linux/list.h>

struct hide_file_info {
    struct qstr path;
    struct dentry* dentry;
    struct hlist_node node; // TODO: consider using hlist_bl_node for locks
};

#define HIDE_FILE_HASH_TABLE_BITS 8

extern DECLARE_HASHTABLE(hide_file_info_list, HIDE_FILE_HASH_TABLE_BITS);

int hide_file_init(void);
int hide_file_exit(void);
int hide_file_add(const char *pathname);
int hide_file_del(const char *pathname);

#endif