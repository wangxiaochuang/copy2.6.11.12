#include <linux/config.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <asm/semaphore.h>

#include "base.h"
#include "power/power.h"

int (*platform_notify)(struct device * dev) = NULL;
int (*platform_notify_remove)(struct device * dev) = NULL;

#define to_dev(obj) container_of(obj, struct device, kobj)
#define to_dev_attr(_attr) container_of(_attr, struct device_attribute, attr)

extern struct attribute * dev_default_attrs[];

static ssize_t
dev_attr_show(struct kobject * kobj, struct attribute * attr, char * buf)
{
    return 0;
}

static ssize_t
dev_attr_store(struct kobject * kobj, struct attribute * attr,
	       const char * buf, size_t count)
{
    return 0;
}

static struct sysfs_ops dev_sysfs_ops = {
	.show	= dev_attr_show,
	.store	= dev_attr_store,
};

static void device_release(struct kobject * kobj)
{
}



static struct kobj_type ktype_device = {
	.release	= device_release,
	.sysfs_ops	= &dev_sysfs_ops,
	.default_attrs	= dev_default_attrs,
};

static int dev_hotplug_filter(struct kset *kset, struct kobject *kobj)
{
    struct kobj_type *ktype = get_ktype(kobj);

	if (ktype == &ktype_device) {
		struct device *dev = to_dev(kobj);
		if (dev->bus)
			return 1;
	}
	return 0;
}

static char *dev_hotplug_name(struct kset *kset, struct kobject *kobj)
{
    return NULL;
}

static int dev_hotplug(struct kset *kset, struct kobject *kobj, char **envp,
			int num_envp, char *buffer, int buffer_size)
{
    return 0;
}

static struct kset_hotplug_ops device_hotplug_ops = {
	.filter =	dev_hotplug_filter,
	.name =		dev_hotplug_name,
	.hotplug =	dev_hotplug,
};

decl_subsys(devices, &ktype_device, &device_hotplug_ops);


int device_create_file(struct device * dev, struct device_attribute * attr)
{
	int error = 0;
	if (get_device(dev)) {
		error = sysfs_create_file(&dev->kobj, &attr->attr);
		put_device(dev);
	}
	return error;
}

void device_remove_file(struct device * dev, struct device_attribute * attr)
{
	if (get_device(dev)) {
		sysfs_remove_file(&dev->kobj, &attr->attr);
		put_device(dev);
	}
}

void device_initialize(struct device *dev)
{
	kobj_set_kset_s(dev, devices_subsys);
	kobject_init(&dev->kobj);
	INIT_LIST_HEAD(&dev->node);
	INIT_LIST_HEAD(&dev->children);
	INIT_LIST_HEAD(&dev->driver_list);
	INIT_LIST_HEAD(&dev->bus_list);
	INIT_LIST_HEAD(&dev->dma_pools);
}

int device_add(struct device *dev)
{
	struct device *parent = NULL;
	int error = -EINVAL;

	dev = get_device(dev);
	if (!dev || !strlen(dev->bus_id))
		goto Error;

	parent = get_device(dev->parent);

	pr_debug("DEV: registering device: ID = '%s'\n", dev->bus_id);

	kobject_set_name(&dev->kobj, "%s", dev->bus_id);
	if (parent)
		dev->kobj.parent = &parent->kobj;

	if ((error = kobject_add(&dev->kobj)))
		goto Error;
	if ((error = device_pm_add(dev)))
		goto PMError;
	if ((error = bus_add_device(dev)))
		goto BusError;
	down_write(&devices_subsys.rwsem);
	if (parent)
		list_add_tail(&dev->node, &parent->children);
	up_write(&devices_subsys.rwsem);

	if (platform_notify)
		platform_notify(dev);
 Done:
	put_device(dev);
	return error;
 BusError:
	device_pm_remove(dev);
 PMError:
	kobject_del(&dev->kobj);
 Error:
	if (parent)
		put_device(parent);
	goto Done;
}

int device_register(struct device *dev)
{
	device_initialize(dev);
	return device_add(dev);
}

struct device *get_device(struct device *dev)
{
	return dev ? to_dev(kobject_get(&dev->kobj)) : NULL;
}

void put_device(struct device * dev)
{
	if (dev)
		kobject_put(&dev->kobj);
}

int __init devices_init(void)
{
	return subsystem_register(&devices_subsys);
}