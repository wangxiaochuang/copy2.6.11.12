#include <linux/config.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/err.h>

struct class_simple {
	struct class_device_attribute attr;
	struct class class;
};
#define to_class_simple(d) container_of(d, struct class_simple, class)

struct simple_dev {
	struct list_head node;
	dev_t dev;
	struct class_device class_dev;
};
#define to_simple_dev(d) container_of(d, struct simple_dev, class_dev)

static LIST_HEAD(simple_dev_list);
static DEFINE_SPINLOCK(simple_dev_list_lock);

struct class_simple *class_simple_create(struct module *owner, char *name)
{
	panic("in class_simple_create");
	return NULL;
}