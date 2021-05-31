#include <linux/fs.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/namei.h>

#include "sysfs.h"

static int sysfs_add_link(struct dentry * parent, char * name, struct kobject * target)
{
	struct sysfs_dirent * parent_sd = parent->d_fsdata;
	struct sysfs_symlink * sl;
	int error = 0;

	error = -ENOMEM;
	sl = kmalloc(sizeof(*sl), GFP_KERNEL);
	if (!sl)
		goto exit1;

	sl->link_name = kmalloc(strlen(name) + 1, GFP_KERNEL);
	if (!sl->link_name)
		goto exit2;

	strcpy(sl->link_name, name);
	sl->target_kobj = kobject_get(target);

	error = sysfs_make_dirent(parent_sd, NULL, sl, S_IFLNK|S_IRWXUGO,
				SYSFS_KOBJ_LINK);
	if (!error)
		return 0;

	kfree(sl->link_name);
exit2:
	kfree(sl);
exit1:
	return error;
}

int sysfs_create_link(struct kobject * kobj, struct kobject * target, char * name)
{
	struct dentry * dentry = kobj->dentry;
	int error = 0;

	BUG_ON(!kobj || !kobj->dentry || !name);

	down(&dentry->d_inode->i_sem);
	error = sysfs_add_link(dentry, name, target);
	up(&dentry->d_inode->i_sem);
	return error;
}

static int sysfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
    return 0;
}

static void sysfs_put_link(struct dentry *dentry, struct nameidata *nd)
{
}

struct inode_operations sysfs_symlink_inode_operations = {
	.readlink = generic_readlink,
	.follow_link = sysfs_follow_link,
	.put_link = sysfs_put_link,
};