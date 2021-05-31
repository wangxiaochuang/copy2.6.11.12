#include <linux/config.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/string.h>
#include "base.h"
#include "power/power.h"

#define to_dev(node) container_of(node, struct device, bus_list)
#define to_drv(node) container_of(node, struct device_driver, kobj.entry)

#define to_bus_attr(_attr) container_of(_attr, struct bus_attribute, attr)
#define to_bus(obj) container_of(obj, struct bus_type, subsys.kset.kobj)

#define to_drv_attr(_attr) container_of(_attr, struct driver_attribute, attr)
#define to_driver(obj) container_of(obj, struct device_driver, kobj)

static ssize_t
drv_attr_show(struct kobject * kobj, struct attribute * attr, char * buf)
{
	return 0;
}

static ssize_t
drv_attr_store(struct kobject * kobj, struct attribute * attr,
	       const char * buf, size_t count)
{
	return 0;
}

static struct sysfs_ops driver_sysfs_ops = {
	.show	= drv_attr_show,
	.store	= drv_attr_store,
};

static void driver_release(struct kobject * kobj)
{
	struct device_driver * drv = to_driver(kobj);
	up(&drv->unload_sem);
}

static struct kobj_type ktype_driver = {
	.sysfs_ops	= &driver_sysfs_ops,
	.release	= driver_release,
};

static ssize_t
bus_attr_show(struct kobject * kobj, struct attribute * attr, char * buf)
{
    return 0;
}

static ssize_t
bus_attr_store(struct kobject * kobj, struct attribute * attr,
	       const char * buf, size_t count)
{
    return 0;
}

static struct sysfs_ops bus_sysfs_ops = {
	.show	= bus_attr_show,
	.store	= bus_attr_store,
};

int bus_create_file(struct bus_type * bus, struct bus_attribute * attr)
{
	int error;
	if (get_bus(bus)) {
		error = sysfs_create_file(&bus->subsys.kset.kobj, &attr->attr);
		put_bus(bus);
	} else
		error = -EINVAL;
	return error;
}

void bus_remove_file(struct bus_type * bus, struct bus_attribute * attr)
{
	if (get_bus(bus)) {
		sysfs_remove_file(&bus->subsys.kset.kobj, &attr->attr);
		put_bus(bus);
	}
}

static struct kobj_type ktype_bus = {
	.sysfs_ops	= &bus_sysfs_ops,
};

decl_subsys(bus, &ktype_bus, NULL);

void device_bind_driver(struct device * dev)
{
	pr_debug("bound device '%s' to driver '%s'\n",
		 dev->bus_id, dev->driver->name);
	list_add_tail(&dev->driver_list, &dev->driver->devices);
	sysfs_create_link(&dev->driver->kobj, &dev->kobj,
			kobject_name(&dev->kobj));
	sysfs_create_link(&dev->kobj, &dev->driver->kobj, "driver");
}

int driver_probe_device(struct device_driver * drv, struct device * dev)
{
	if (drv->bus->match && !drv->bus->match(dev, drv))
		return -ENODEV;

	dev->driver = drv;
	if (drv->probe) {
		int error = drv->probe(dev);
		if (error) {
			dev->driver = NULL;
			return error;
		}
	}
	device_bind_driver(dev);
	return 0;
}

int device_attach(struct device * dev)
{
	struct bus_type *bus = dev->bus;
	struct list_head *entry;
	int error;

	if (dev->driver) {
		device_bind_driver(dev);
		return 1;
	}

	if (bus->match) {
		list_for_each(entry, &bus->drivers.list) {
			struct device_driver * drv = to_drv(entry);
			error = driver_probe_device(drv, dev);
			if (!error)
				/* success, driver matched */
				return 1;
			if (error != -ENODEV && error != -ENXIO)
				/* driver matched but the probe failed */
				printk(KERN_WARNING
				    "%s: probe of %s failed with error %d\n",
				    drv->name, dev->bus_id, error);
		}
	}
	return 0;
}

static int device_add_attrs(struct bus_type * bus, struct device * dev)
{
	int error = 0;
	int i;

	if (bus->dev_attrs) {
		for (i = 0; attr_name(bus->dev_attrs[i]); i++) {
			error = device_create_file(dev,&bus->dev_attrs[i]);
			if (error)
				goto Err;
		}
	}
 Done:
	return error;
 Err:
	while (--i >= 0)
		device_remove_file(dev,&bus->dev_attrs[i]);
	goto Done;
}

int bus_add_device(struct device * dev)
{
	struct bus_type * bus = get_bus(dev->bus);
	int error = 0;

	if (bus) {
		down_write(&dev->bus->subsys.rwsem);
		pr_debug("bus %s: add device %s\n", bus->name, dev->bus_id);
		list_add_tail(&dev->bus_list, &dev->bus->devices.list);
		device_attach(dev);
		up_write(&dev->bus->subsys.rwsem);
		device_add_attrs(bus, dev);
		sysfs_create_link(&bus->devices.kobj, &dev->kobj, dev->bus_id);
	}
	return error;
}

struct bus_type * get_bus(struct bus_type * bus)
{
	return bus ? container_of(subsys_get(&bus->subsys), struct bus_type, subsys) : NULL;
}

void put_bus(struct bus_type * bus)
{
	subsys_put(&bus->subsys);
}

struct bus_type * find_bus(char * name)
{
    return NULL;
}

static int bus_add_attrs(struct bus_type * bus)
{
	int error = 0;
	int i;

	if (bus->bus_attrs) {
		for (i = 0; attr_name(bus->bus_attrs[i]); i++) {
			if ((error = bus_create_file(bus,&bus->bus_attrs[i])))
				goto Err;
		}
	}
 Done:
	return error;
 Err:
	while (--i >= 0)
		bus_remove_file(bus,&bus->bus_attrs[i]);
	goto Done;
}

static void bus_remove_attrs(struct bus_type * bus)
{
	int i;

	if (bus->bus_attrs) {
		for (i = 0; attr_name(bus->bus_attrs[i]); i++)
			bus_remove_file(bus,&bus->bus_attrs[i]);
	}
}

int bus_register(struct bus_type * bus)
{
	int retval;

	retval = kobject_set_name(&bus->subsys.kset.kobj, "%s", bus->name);
	if (retval)
		goto out;

	subsys_set_kset(bus, bus_subsys);
	retval = subsystem_register(&bus->subsys);
	if (retval)
		goto out;

	kobject_set_name(&bus->devices.kobj, "devices");
	bus->devices.subsys = &bus->subsys;
	retval = kset_register(&bus->devices);
	if (retval)
		goto bus_devices_fail;

	kobject_set_name(&bus->drivers.kobj, "drivers");
	bus->drivers.subsys = &bus->subsys;
	bus->drivers.ktype = &ktype_driver;
	retval = kset_register(&bus->drivers);
	if (retval)
		goto bus_drivers_fail;
	bus_add_attrs(bus);

	pr_debug("bus type '%s' registered\n", bus->name);
	return 0;

bus_drivers_fail:
	kset_unregister(&bus->devices);
bus_devices_fail:
	subsystem_unregister(&bus->subsys);
out:
	return retval;
}

void bus_unregister(struct bus_type * bus)
{
}

int __init buses_init(void)
{
	return subsystem_register(&bus_subsys);
}