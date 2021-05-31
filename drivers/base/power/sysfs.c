#include <linux/device.h>
#include "power.h"

static ssize_t state_show(struct device * dev, char * buf)
{
	return sprintf(buf, "%u\n", dev->power.power_state);
}

static ssize_t state_store(struct device * dev, const char * buf, size_t n)
{
    return 0;
}

static DEVICE_ATTR(state, 0644, state_show, state_store);

static struct attribute * power_attrs[] = {
	&dev_attr_state.attr,
	NULL,
};
static struct attribute_group pm_attr_group = {
	.name	= "power",
	.attrs	= power_attrs,
};

int dpm_sysfs_add(struct device * dev)
{
	return sysfs_create_group(&dev->kobj, &pm_attr_group);
}

void dpm_sysfs_remove(struct device * dev)
{
	sysfs_remove_group(&dev->kobj, &pm_attr_group);
}