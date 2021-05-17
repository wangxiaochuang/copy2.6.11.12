#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/idr.h>
#include <linux/namei.h>
#include <linux/bitops.h>
#include <asm/uaccess.h>

static ssize_t proc_file_read(struct file *file, char __user *buf,
			      size_t nbytes, loff_t *ppos);
static ssize_t proc_file_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *ppos);
static loff_t proc_file_lseek(struct file *, loff_t, int);

int proc_match(int len, const char *name, struct proc_dir_entry *de)
{
	if (de->namelen != len)
		return 0;
	return !memcmp(name, de->name, len);
}

static struct file_operations proc_file_operations = {
	.llseek		= proc_file_lseek,
	.read		= proc_file_read,
	.write		= proc_file_write,
};

static ssize_t
proc_file_read(struct file *file, char __user *buf, size_t nbytes,
	       loff_t *ppos)
{
	panic("in proc_file_read function");
	return 0;
}

static ssize_t
proc_file_write(struct file *file, const char __user *buffer,
		size_t count, loff_t *ppos)
{
	panic("in proc_file_write function");
	return 0;
}

static loff_t
proc_file_lseek(struct file *file, loff_t offset, int orig)
{
	panic("in proc_file_lseek function");
	return 0;
}


static int proc_notify_change(struct dentry *dentry, struct iattr *iattr)
{
	panic("in proc_notify_change function");
	return 0;
}

static struct inode_operations proc_file_inode_operations = {
	.setattr	= proc_notify_change,
};

/*
 * This function parses a name such as "tty/driver/serial", and
 * returns the struct proc_dir_entry for "/proc/tty/driver", and
 * returns "serial" in residual.
 */
static int xlate_proc_name(const char *name,
			   struct proc_dir_entry **ret, const char **residual)
{
	const char     		*cp = name, *next;
	struct proc_dir_entry	*de;
	int			len;

	de = &proc_root;
	while (1) {
		next = strchr(cp, '/');
		if (!next)
			break;

		len = next - cp;
		for (de = de->subdir; de ; de = de->next) {
			if (proc_match(len, cp, de))
				break;
		}
		if (!de)
			return -ENOENT;
		cp += len + 1;
	}
	*residual = cp;
	*ret = de;
	return 0;
}

static DEFINE_IDR(proc_inum_idr);
static DEFINE_SPINLOCK(proc_inum_lock); /* protects the above */

#define PROC_DYNAMIC_FIRST 0xF0000000UL

static unsigned int get_inode_number(void)
{
	int i, inum = 0;
	int error;

retry:
	if (idr_pre_get(&proc_inum_idr, GFP_KERNEL) == 0)
		return 0;

	spin_lock(&proc_inum_lock);
	error = idr_get_new(&proc_inum_idr, NULL, &i);
	spin_unlock(&proc_inum_lock);
	if (error == -EAGAIN)
		goto retry;
	else if (error)
		return 0;

	inum = (i & MAX_ID_MASK) + PROC_DYNAMIC_FIRST;

	/* inum will never be more than 0xf0ffffff, so no check
	 * for overflow.
	 */

	return inum;
}

static void release_inode_number(unsigned int inum)
{
	int id = (inum - PROC_DYNAMIC_FIRST) | ~MAX_ID_MASK;

	spin_lock(&proc_inum_lock);
	idr_remove(&proc_inum_idr, id);
	spin_unlock(&proc_inum_lock);
}

static int proc_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	panic("in proc_follow_link function");
	return 0;
}

static struct inode_operations proc_link_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= proc_follow_link,
};

static int proc_delete_dentry(struct dentry * dentry)
{
	return 1;
}

static struct dentry_operations proc_dentry_operations =
{
	.d_delete	= proc_delete_dentry,
};

struct dentry *proc_lookup(struct inode * dir, struct dentry *dentry, struct nameidata *nd)
{
	panic("in proc_lookup function");
	return NULL;
}

int proc_readdir(struct file * filp,
	void * dirent, filldir_t filldir)
{
	panic("in proc_readdir function");
	return 0;
}

/*
 * These are the generic /proc directory operations. They
 * use the in-memory "struct proc_dir_entry" tree to parse
 * the /proc directory.
 */
static struct file_operations proc_dir_operations = {
	.read			= generic_read_dir,
	.readdir		= proc_readdir,
};

/*
 * proc directories can do almost nothing..
 */
static struct inode_operations proc_dir_inode_operations = {
	.lookup		= proc_lookup,
	.setattr	= proc_notify_change,
};

static int proc_register(struct proc_dir_entry * dir, struct proc_dir_entry * dp)
{
	unsigned int i;
	
	i = get_inode_number();
	if (i == 0)
		return -EAGAIN;
	dp->low_ino = i;
	dp->next = dir->subdir;
	dp->parent = dir;
	dir->subdir = dp;
	if (S_ISDIR(dp->mode)) {
		if (dp->proc_iops == NULL) {
			dp->proc_fops = &proc_dir_operations;
			dp->proc_iops = &proc_dir_inode_operations;
		}
		dir->nlink++;
	} else if (S_ISLNK(dp->mode)) {
		if (dp->proc_iops == NULL)
			dp->proc_iops = &proc_link_inode_operations;
	} else if (S_ISREG(dp->mode)) {
		if (dp->proc_fops == NULL)
			dp->proc_fops = &proc_file_operations;
		if (dp->proc_iops == NULL)
			dp->proc_iops = &proc_file_inode_operations;
	}
	return 0;
}

static struct proc_dir_entry *proc_create(struct proc_dir_entry **parent,
					  const char *name,
					  mode_t mode,
					  nlink_t nlink)
{
	struct proc_dir_entry *ent = NULL;
	const char *fn = name;
	int len;

	/* make sure name is valid */
	if (!name || !strlen(name)) goto out;

	if (!(*parent) && xlate_proc_name(name, parent, &fn) != 0)
		goto out;

	/* At this point there must not be any '/' characters beyond *fn */
	if (strchr(fn, '/'))
		goto out;

	len = strlen(fn);

	ent = kmalloc(sizeof(struct proc_dir_entry) + len + 1, GFP_KERNEL);
	if (!ent) goto out;

	memset(ent, 0, sizeof(struct proc_dir_entry));
	memcpy(((char *) ent) + sizeof(struct proc_dir_entry), fn, len + 1);
	ent->name = ((char *) ent) + sizeof(*ent);
	ent->namelen = len;
	ent->mode = mode;
	ent->nlink = nlink;
 out:
	return ent;
}

struct proc_dir_entry *proc_symlink(const char *name,
		struct proc_dir_entry *parent, const char *dest)
{
	struct proc_dir_entry *ent;

	ent = proc_create(&parent,name,
			  (S_IFLNK | S_IRUGO | S_IWUGO | S_IXUGO),1);

	if (ent) {
		ent->data = kmalloc((ent->size=strlen(dest))+1, GFP_KERNEL);
		if (ent->data) {
			strcpy((char*)ent->data,dest);
			if (proc_register(parent, ent) < 0) {
				kfree(ent->data);
				kfree(ent);
				ent = NULL;
			}
		} else {
			kfree(ent);
			ent = NULL;
		}
	}
	return ent;
}

struct proc_dir_entry *proc_mkdir_mode(const char *name, mode_t mode,
		struct proc_dir_entry *parent)
{
	struct proc_dir_entry *ent;

	ent = proc_create(&parent, name, S_IFDIR | mode, 2);
	if (ent) {
		ent->proc_fops = &proc_dir_operations;
		ent->proc_iops = &proc_dir_inode_operations;

		if (proc_register(parent, ent) < 0) {
			kfree(ent);
			ent = NULL;
		}
	}
	return ent;
}

struct proc_dir_entry *proc_mkdir(const char *name,
		struct proc_dir_entry *parent)
{
	return proc_mkdir_mode(name, S_IRUGO | S_IXUGO, parent);
}

struct proc_dir_entry *create_proc_entry(const char *name, mode_t mode,
					 struct proc_dir_entry *parent)
{
	struct proc_dir_entry *ent;
	nlink_t nlink;

	if (S_ISDIR(mode)) {
		if ((mode & S_IALLUGO) == 0)
			mode |= S_IRUGO | S_IXUGO;
		nlink = 2;
	} else {
		if ((mode & S_IFMT) == 0)
			mode |= S_IFREG;
		if ((mode & S_IALLUGO) == 0)
			mode |= S_IRUGO;
		nlink = 1;
	}

	ent = proc_create(&parent,name,mode,nlink);
	if (ent) {
		if (S_ISDIR(mode)) {
			ent->proc_fops = &proc_dir_operations;
			ent->proc_iops = &proc_dir_inode_operations;
		}
		if (proc_register(parent, ent) < 0) {
			kfree(ent);
			ent = NULL;
		}
	}
	return ent;
}

void free_proc_entry(struct proc_dir_entry *de)
{
	unsigned int ino = de->low_ino;

	if (ino < PROC_DYNAMIC_FIRST)
		return;

	release_inode_number(ino);

	if (S_ISLNK(de->mode) && de->data)
		kfree(de->data);
	kfree(de);
}