#include <asm/uaccess.h>

#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/config.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/smp_lock.h>

static struct super_block *proc_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return get_sb_single(fs_type, flags, data, proc_fill_super);
}

static struct file_system_type proc_fs_type = {
	.name		= "proc",
	.get_sb		= proc_get_sb,
	.kill_sb	= kill_anon_super,
};

extern int __init proc_init_inodecache(void);
void __init proc_root_init(void)
{
    int err = proc_init_inodecache();
	if (err)
		return;
	err = register_filesystem(&proc_fs_type);
	if (err)
		return;
	proc_mnt = kern_mount(&proc_fs_type);
	err = PTR_ERR(proc_mnt);
	if (IS_ERR(proc_mnt)) {
		unregister_filesystem(&proc_fs_type);
		return;
	}
}

static struct dentry *proc_root_lookup(struct inode * dir, struct dentry * dentry, struct nameidata *nd)
{
    return NULL;
}

static int proc_root_readdir(struct file * filp,
	void * dirent, filldir_t filldir)
{
    return 0;
}

static struct file_operations proc_root_operations = {
	.read		 = generic_read_dir,
	.readdir	 = proc_root_readdir,
};

/*
 * proc root can do almost nothing..
 */
static struct inode_operations proc_root_inode_operations = {
	.lookup		= proc_root_lookup,
};

struct proc_dir_entry proc_root = {
	.low_ino	= PROC_ROOT_INO, 
	.namelen	= 5, 
	.name		= "/proc",
	.mode		= S_IFDIR | S_IRUGO | S_IXUGO, 
	.nlink		= 2, 
	.proc_iops	= &proc_root_inode_operations, 
	.proc_fops	= &proc_root_operations,
	.parent		= &proc_root,
};