#include <linux/config.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/devfs_fs_kernel.h>

#include <linux/kobject.h>
#include <linux/kobj_map.h>
#include <linux/cdev.h>

static struct kobj_map *cdev_map;

static DEFINE_SPINLOCK(cdev_lock);

void cdev_put(struct cdev *p)
{
	if (p) {
		kobject_put(&p->kobj);
		module_put(p->owner);
	}
}

int chrdev_open(struct inode * inode, struct file * filp)
{
	panic("in chrdev_open function");
	return 0;
}

void cd_forget(struct inode *inode)
{
	spin_lock(&cdev_lock);
	list_del_init(&inode->i_devices);
	inode->i_cdev = NULL;
	spin_unlock(&cdev_lock);
}

struct file_operations def_chr_fops = {
	.open = chrdev_open,
};

static decl_subsys(cdev, NULL, NULL);

static struct kobject *base_probe(dev_t dev, int *part, void *data)
{
	if (request_module("char-major-%d-%d", MAJOR(dev), MINOR(dev)) > 0)
		/* Make old-style 2.4 aliases work */
		request_module("char-major-%d", MAJOR(dev));
	return NULL;
}

void __init chrdev_init(void)
{
	subsystem_init(&cdev_subsys);
	cdev_map = kobj_map_init(base_probe, &cdev_subsys);
}