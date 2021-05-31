#include <linux/sysdev.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/topology.h>
#include <linux/device.h>


struct sysdev_class cpu_sysdev_class = {
	set_kset_name("cpu"),
};
EXPORT_SYMBOL(cpu_sysdev_class);


int __init cpu_dev_init(void)
{
	return sysdev_class_register(&cpu_sysdev_class);
}
