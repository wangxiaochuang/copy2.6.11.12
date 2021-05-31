#include <linux/attribute_container.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/module.h>

static struct list_head attribute_container_list;

int __init
attribute_container_init(void)
{
	INIT_LIST_HEAD(&attribute_container_list);
	return 0;
}