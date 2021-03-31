#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

struct list_head {
	struct list_head *next, *prev;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

#endif
