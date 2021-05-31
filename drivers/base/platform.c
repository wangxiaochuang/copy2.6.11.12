#include <linux/device.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/dma-mapping.h>
#include <linux/bootmem.h>
#include <linux/err.h>

struct device platform_bus = {
	.bus_id		= "platform",
};




static int platform_match(struct device * dev, struct device_driver * drv)
{
    return 0;
}

static int platform_suspend(struct device * dev, pm_message_t state)
{
    return 0;
}

static int platform_resume(struct device * dev)
{
    return 0;
}

struct bus_type platform_bus_type = {
	.name		= "platform",
	.match		= platform_match,
	.suspend	= platform_suspend,
	.resume		= platform_resume,
};

int __init platform_bus_init(void)
{
	device_register(&platform_bus);
	return bus_register(&platform_bus_type);
}