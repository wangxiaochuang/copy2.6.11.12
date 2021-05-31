#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/stat.h>

static int populate_dir(struct kobject * kobj)
{
	struct kobj_type *t = get_ktype(kobj);
	struct attribute *attr;
	int error = 0;
	int i;

	if (t && t->default_attrs) {
		for (i = 0; (attr = t->default_attrs[i]) != NULL; i++) {
			if ((error = sysfs_create_file(kobj, attr)))
				break;
		}
	}
	return error;
}

static int create_dir(struct kobject * kobj)
{
	int error = 0;
	if (kobject_name(kobj)) {
		error = sysfs_create_dir(kobj);
		if (!error) {
			if ((error = populate_dir(kobj)))
				sysfs_remove_dir(kobj);
		}	
	}
	return error;
}

static inline struct kobject * to_kobj(struct list_head * entry)
{
	return container_of(entry,struct kobject,entry);
}

static int get_kobj_path_length(struct kobject *kobj)
{
	int length = 1;
	struct kobject * parent = kobj;

	do {
		length += strlen(kobject_name(parent)) + 1;
		parent = parent->parent;
	} while (parent);
	return length;
}

static void fill_kobj_path(struct kobject *kobj, char *path, int length)
{
	struct kobject * parent;

	--length;
	for (parent = kobj; parent; parent = parent->parent) {
		int cur = strlen(kobject_name(parent));
		length -= cur;
		strncpy(path + length, kobject_name(parent), cur);
		*(path + --length) = '/';
	}

	pr_debug("%s: path = '%s'\n",__FUNCTION__,path);
}

char *kobject_get_path(struct kobject *kobj, int gfp_mask)
{
	char *path;
	int len;

	len = get_kobj_path_length(kobj);
	path = kmalloc(len, gfp_mask);
	if (!path)
		return NULL;
	memset(path, 0x00, len);
	fill_kobj_path(kobj, path, len);

	return path;
}

void kobject_init(struct kobject * kobj)
{
	kref_init(&kobj->kref);
	INIT_LIST_HEAD(&kobj->entry);
	kobj->kset = kset_get(kobj->kset);
}

static void unlink(struct kobject * kobj)
{
	if (kobj->kset) {
		down_write(&kobj->kset->subsys->rwsem);
		list_del_init(&kobj->entry);
		up_write(&kobj->kset->subsys->rwsem);
	}
	kobject_put(kobj);
}

int kobject_add(struct kobject * kobj)
{
	int error = 0;
	struct kobject *parent;

	if (!(kobj = kobject_get(kobj)))
		return -ENOENT;
	if (!kobj->k_name)
		kobj->k_name = kobj->name;
	parent = kobject_get(kobj->parent);

	pr_debug("kobject %s: registering. parent: %s, set: %s\n",
		 kobject_name(kobj), parent ? kobject_name(parent) : "<NULL>", 
		 kobj->kset ? kobj->kset->kobj.name : "<NULL>" );

	if (kobj->kset) {
		down_write(&kobj->kset->subsys->rwsem);

		if (!parent)
			parent = kobject_get(&kobj->kset->kobj);

		list_add_tail(&kobj->entry, &kobj->kset->list);
		up_write(&kobj->kset->subsys->rwsem);
	}
	kobj->parent = parent;

	error = create_dir(kobj);
	if (error) {
		unlink(kobj);
		if (parent)
			kobject_put(parent);
	} else {
		kobject_hotplug(kobj, KOBJ_ADD);
	}

	return error;
}

int kobject_register(struct kobject * kobj)
{
	return 0;
}

int kobject_set_name(struct kobject * kobj, const char * fmt, ...)
{
	int error = 0;
	int limit = KOBJ_NAME_LEN;
	int need;
	va_list args;
	char * name;

	va_start(args, fmt);
	need = vsnprintf(kobj->name, limit, fmt, args);
	va_end(args);
	if (need < limit) {
		name = kobj->name;
	} else {
		limit = need + 1;
		name = kmalloc(limit, GFP_KERNEL);
		if (!name) {
			error = -ENOMEM;
			goto Done;
		}
		va_start(args, fmt);
		need = vsnprintf(name, limit, fmt, args);
		va_end(args);

		if (need >= limit) {
			kfree(name);
			error = -EFAULT;
			goto Done;
		}
	}

	if (kobj->k_name && kobj->k_name != kobj->name)
		kfree(kobj->k_name);

	kobj->k_name = name;
Done:
	return error;
}

void kobject_del(struct kobject * kobj)
{
	kobject_hotplug(kobj, KOBJ_REMOVE);
	sysfs_remove_dir(kobj);
	unlink(kobj);
}

void kobject_unregister(struct kobject * kobj)
{
	pr_debug("kobject %s: unregistering\n",kobject_name(kobj));
	kobject_del(kobj);
	kobject_put(kobj);
}

struct kobject * kobject_get(struct kobject * kobj)
{
	if (kobj)
		kref_get(&kobj->kref);
	return kobj;
}

void kobject_cleanup(struct kobject * kobj)
{
	struct kobj_type * t = get_ktype(kobj);
	struct kset * s = kobj->kset;
	struct kobject * parent = kobj->parent;

	pr_debug("kobject %s: cleaning up\n",kobject_name(kobj));
	if (kobj->k_name != kobj->name)
		kfree(kobj->k_name);
	kobj->k_name = NULL;
	if (t && t->release)
		t->release(kobj);
	if (s)
		kset_put(s);
	if (parent) 
		kobject_put(parent);
}

static void kobject_release(struct kref *kref)
{
	kobject_cleanup(container_of(kref, struct kobject, kref));
}

void kobject_put(struct kobject * kobj)
{
	if (kobj)
		kref_put(&kobj->kref, kobject_release);
}

void kset_init(struct kset * k)
{
	kobject_init(&k->kobj);
	INIT_LIST_HEAD(&k->list);
}

int kset_add(struct kset * k)
{
	if (!k->kobj.parent && !k->kobj.kset && k->subsys)
		k->kobj.parent = &k->subsys->kset.kobj;

	return kobject_add(&k->kobj);
}

int kset_register(struct kset * k)
{
	kset_init(k);
	return kset_add(k);
}

void kset_unregister(struct kset * k)
{
	kobject_unregister(&k->kobj);
}

void subsystem_init(struct subsystem * s)
{
	init_rwsem(&s->rwsem);
	kset_init(&s->kset);
}

int subsystem_register(struct subsystem * s)
{
	int error;

	subsystem_init(s);
	pr_debug("subsystem %s: registering\n",s->kset.kobj.name);

	if (!(error = kset_add(&s->kset))) {
		if (!s->kset.subsys)
			s->kset.subsys = s;
	}
	return error;
}

void subsystem_unregister(struct subsystem * s)
{
	pr_debug("subsystem %s: unregistering\n",s->kset.kobj.name);
	kset_unregister(&s->kset);
}