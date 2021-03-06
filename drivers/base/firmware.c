#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/init.h>

static decl_subsys(firmware, NULL, NULL);

int firmware_register(struct subsystem * s)
{
	kset_set_kset_s(s, firmware_subsys);
	return subsystem_register(s);
}

void firmware_unregister(struct subsystem * s)
{
	subsystem_unregister(s);
}

int __init firmware_init(void)
{
	return subsystem_register(&firmware_subsys);
}

EXPORT_SYMBOL_GPL(firmware_register);
EXPORT_SYMBOL_GPL(firmware_unregister);