#include <linux/config.h>
#include <linux/device.h>
#include "power.h"

LIST_HEAD(dpm_active);
LIST_HEAD(dpm_off);
LIST_HEAD(dpm_off_irq);

DECLARE_MUTEX(dpm_sem);
DECLARE_MUTEX(dpm_list_sem);

static inline void device_pm_hold(struct device * dev)
{
	if (dev)
		atomic_inc(&dev->power.pm_users);
}

static inline void device_pm_release(struct device * dev)
{
	if (dev)
		atomic_dec(&dev->power.pm_users);
}

void device_pm_set_parent(struct device * dev, struct device * parent)
{
    struct device *old_parent = dev->power.pm_parent;
    device_pm_release(old_parent);
    dev->power.pm_parent = parent;
    device_pm_hold(parent);
}

EXPORT_SYMBOL_GPL(device_pm_set_parent);

int device_pm_add(struct device * dev)
{
	int error;

	pr_debug("PM: Adding info for %s:%s\n",
		 dev->bus ? dev->bus->name : "No Bus", dev->kobj.name);
    atomic_set(&dev->power.pm_users, 0);
    down(&dpm_list_sem);
    list_add_tail(&dev->power.entry, &dpm_active);
    device_pm_set_parent(dev, dev->parent);
    if ((error = dpm_sysfs_add(dev)))
        list_del(&dev->power.entry);
    up(&dpm_list_sem);
    return error;
}

void device_pm_remove(struct device * dev)
{
}