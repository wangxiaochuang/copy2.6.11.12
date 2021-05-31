#include <linux/config.h>
#include <linux/sysdev.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>


extern struct subsystem devices_subsys;

#define to_sysdev(k) container_of(k, struct sys_device, kobj)
#define to_sysdev_attr(a) container_of(a, struct sysdev_attribute, attr)

static ssize_t
sysdev_show(struct kobject * kobj, struct attribute * attr, char * buffer)
{
    return 0;
}

static ssize_t
sysdev_store(struct kobject * kobj, struct attribute * attr,
	     const char * buffer, size_t count)
{
    return 0;
}

static struct sysfs_ops sysfs_ops = {
	.show	= sysdev_show,
	.store	= sysdev_store,
};

static struct kobj_type ktype_sysdev = {
	.sysfs_ops	= &sysfs_ops,
};

int sysdev_create_file(struct sys_device * s, struct sysdev_attribute * a)
{
	return sysfs_create_file(&s->kobj, &a->attr);
}


void sysdev_remove_file(struct sys_device * s, struct sysdev_attribute * a)
{
	sysfs_remove_file(&s->kobj, &a->attr);
}

EXPORT_SYMBOL_GPL(sysdev_create_file);
EXPORT_SYMBOL_GPL(sysdev_remove_file);


decl_subsys(system, &ktype_sysdev, NULL);

int sysdev_class_register(struct sysdev_class * cls)
{
	pr_debug("Registering sysdev class '%s'\n",
		 kobject_name(&cls->kset.kobj));
	INIT_LIST_HEAD(&cls->drivers);
	cls->kset.subsys = &system_subsys;
	kset_set_kset_s(cls, system_subsys);
	return kset_register(&cls->kset);
}

void sysdev_class_unregister(struct sysdev_class * cls)
{
	pr_debug("Unregistering sysdev class '%s'\n",
		 kobject_name(&cls->kset.kobj));
	kset_unregister(&cls->kset);
}

EXPORT_SYMBOL_GPL(sysdev_class_register);
EXPORT_SYMBOL_GPL(sysdev_class_unregister);


static LIST_HEAD(global_drivers);

int __init system_bus_init(void)
{
	system_subsys.kset.kobj.parent = &devices_subsys.kset.kobj;
	return subsystem_register(&system_subsys);
}
