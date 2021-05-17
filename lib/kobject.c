#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/stat.h>

void kobject_init(struct kobject * kobj)
{
	kref_init(&kobj->kref);
	INIT_LIST_HEAD(&kobj->entry);
	kobj->kset = kset_get(kobj->kset);
}

struct kobject * kobject_get(struct kobject * kobj)
{
	if (kobj)
		kref_get(&kobj->kref);
	return kobj;
}

void kset_init(struct kset * k)
{
	kobject_init(&k->kobj);
	INIT_LIST_HEAD(&k->list);
}

void subsystem_init(struct subsystem * s)
{
	init_rwsem(&s->rwsem);
	kset_init(&s->kset);
}