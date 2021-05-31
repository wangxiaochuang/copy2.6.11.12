#include <linux/device.h>
#include <linux/err.h>
#include <linux/stat.h>
#include <linux/string.h>

static ssize_t detach_show(struct device * dev, char * buf)
{
	return sprintf(buf, "%u\n", dev->detach_state);
}

static ssize_t detach_store(struct device * dev, const char * buf, size_t n)
{
	u32 state;
	state = simple_strtoul(buf, NULL, 10);
	if (state > 4)
		return -EINVAL;
	dev->detach_state = state;
	return n;
}

static DEVICE_ATTR(detach_state, 0644, detach_show, detach_store);

struct attribute * dev_default_attrs[] = {
	&dev_attr_detach_state.attr,
	NULL,
};