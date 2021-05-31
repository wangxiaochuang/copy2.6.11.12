#include <linux/module.h>
#include <linux/dnotify.h>
#include <linux/kobject.h>
#include <asm/uaccess.h>
#include <asm/semaphore.h>

#include "sysfs.h"

#define to_subsys(k) container_of(k,struct subsystem,kset.kobj)
#define to_sattr(a) container_of(a,struct subsys_attribute,attr)





static ssize_t
sysfs_read_file(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    return 0;
}

static ssize_t
sysfs_write_file(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    return 0;
}

static int sysfs_open_file(struct inode * inode, struct file * filp)
{
    return 0;
}

static int sysfs_release(struct inode * inode, struct file * filp)
{
    return 0;
}

struct file_operations sysfs_file_operations = {
	.read		= sysfs_read_file,
	.write		= sysfs_write_file,
	.llseek		= generic_file_llseek,
	.open		= sysfs_open_file,
	.release	= sysfs_release,
};

int sysfs_add_file(struct dentry * dir, const struct attribute * attr, int type)
{
    struct sysfs_dirent *parent_sd = dir->d_fsdata;
    umode_t mode = (attr->mode & S_IALLUGO) | S_IFREG;
    int error = 0;

    down(&dir->d_inode->i_sem);
    error = sysfs_make_dirent(parent_sd, NULL, (void *) attr, mode, type);
	up(&dir->d_inode->i_sem);

	return error;
}

int sysfs_create_file(struct kobject * kobj, const struct attribute * attr)
{
	BUG_ON(!kobj || !kobj->dentry || !attr);

	return sysfs_add_file(kobj->dentry, attr, SYSFS_KOBJ_ATTR);
}

void sysfs_remove_file(struct kobject * kobj, const struct attribute * attr)
{
	sysfs_hash_and_remove(kobj->dentry, attr->name);
}