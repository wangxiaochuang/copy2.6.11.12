#include <linux/config.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include "base.h"

#define to_class_attr(_attr) container_of(_attr, struct class_attribute, attr)
#define to_class(obj) container_of(obj, struct class, subsys.kset.kobj)

static ssize_t
class_attr_show(struct kobject * kobj, struct attribute * attr, char * buf)
{
    return 0;
}

static ssize_t
class_attr_store(struct kobject * kobj, struct attribute * attr,
		 const char * buf, size_t count)
{
    return 0;
}

static void class_release(struct kobject * kobj)
{
}

static struct sysfs_ops class_sysfs_ops = {
	.show	= class_attr_show,
	.store	= class_attr_store,
};

static struct kobj_type ktype_class = {
	.sysfs_ops	= &class_sysfs_ops,
	.release	= class_release,
};

static decl_subsys(class, &ktype_class, NULL);


static ssize_t
class_device_attr_show(struct kobject * kobj, struct attribute * attr,
		       char * buf)
{
    return 0;
}

static ssize_t
class_device_attr_store(struct kobject * kobj, struct attribute * attr,
			const char * buf, size_t count)
{
    return 0;
}

static struct sysfs_ops class_dev_sysfs_ops = {
	.show	= class_device_attr_show,
	.store	= class_device_attr_store,
};

static void class_dev_release(struct kobject * kobj)
{
}

static struct kobj_type ktype_class_device = {
	.sysfs_ops	= &class_dev_sysfs_ops,
	.release	= class_dev_release,
};

static int class_hotplug_filter(struct kset *kset, struct kobject *kobj)
{
    return 0;
}

static char *class_hotplug_name(struct kset *kset, struct kobject *kobj)
{
    return NULL;
}

static int class_hotplug(struct kset *kset, struct kobject *kobj, char **envp,
			 int num_envp, char *buffer, int buffer_size)
{
    return 0;
}

static struct kset_hotplug_ops class_hotplug_ops = {
	.filter =	class_hotplug_filter,
	.name =		class_hotplug_name,
	.hotplug =	class_hotplug,
};

static decl_subsys(class_obj, &ktype_class_device, &class_hotplug_ops);

int __init classes_init(void)
{
	int retval;

    retval = subsystem_register(&class_subsys);
	if (retval)
		return retval;
    
    subsystem_init(&class_obj_subsys);
	if (!class_obj_subsys.kset.subsys)
			class_obj_subsys.kset.subsys = &class_obj_subsys;
    return 0;
}