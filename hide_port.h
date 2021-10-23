#ifndef YARK_HIDE_PORT_H
#define YARK_HIDE_PORT_H

#include <linux/hashtable.h>
#include <linux/list.h>

#define TCP 0
#define UDP 1

struct hide_port_info {
    int port;
    int protocol;
    struct hlist_node node;
};

#define HIDE_PORT_HASH_TABLE_BITS 5

extern DECLARE_HASHTABLE(hide_port_info_list, HIDE_PORT_HASH_TABLE_BITS);

int hide_port_init(void);
int hide_port_exit(void);
int hide_port_add(int port);
int hide_port_del(int port);


#endif