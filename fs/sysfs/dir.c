#undef DEBUG

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include "sysfs.h"

static struct dentry * sysfs_lookup(struct inode *dir, struct dentry *dentry,
				struct nameidata *nd)
{
    panic("in sysfs_lookup function");
    return NULL;
}

struct inode_operations sysfs_dir_inode_operations = {
	.lookup		= sysfs_lookup,
};

static int sysfs_dir_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int sysfs_dir_close(struct inode *inode, struct file *file)
{
    return 0;
}

static int sysfs_readdir(struct file * filp, void * dirent, filldir_t filldir)
{
    return 0;
}

static loff_t sysfs_dir_lseek(struct file * file, loff_t offset, int origin)
{
    return 0;
}

struct file_operations sysfs_dir_operations = {
	.open		= sysfs_dir_open,
	.release	= sysfs_dir_close,
	.llseek		= sysfs_dir_lseek,
	.read		= generic_read_dir,
	.readdir	= sysfs_readdir,
};