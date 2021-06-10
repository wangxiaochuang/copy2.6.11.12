#include <linux/module.h>
#include <linux/dnotify.h>
#include <linux/kobject.h>
#include <asm/uaccess.h>
#include <asm/semaphore.h>

#include "sysfs.h"

#define to_subsys(k) container_of(k,struct subsystem,kset.kobj)
#define to_sattr(a) container_of(a,struct subsys_attribute,attr)

static ssize_t 
subsys_attr_show(struct kobject * kobj, struct attribute * attr, char * page)
{
	struct subsystem * s = to_subsys(kobj);
	struct subsys_attribute * sattr = to_sattr(attr);
	ssize_t ret = 0;

	if (sattr->show)
		ret = sattr->show(s,page);
	return ret;
}

static ssize_t 
subsys_attr_store(struct kobject * kobj, struct attribute * attr, 
		  const char * page, size_t count)
{
	struct subsystem * s = to_subsys(kobj);
	struct subsys_attribute * sattr = to_sattr(attr);
	ssize_t ret = 0;

	if (sattr->store)
		ret = sattr->store(s,page,count);
	return ret;
}

static struct sysfs_ops subsys_sysfs_ops = {
	.show	= subsys_attr_show,
	.store	= subsys_attr_store,
};

struct sysfs_buffer {
	size_t			count;
	loff_t			pos;
	char			* page;
	struct sysfs_ops	* ops;
	struct semaphore	sem;
	int			needs_read_fill;
};

static int fill_read_buffer(struct dentry * dentry, struct sysfs_buffer * buffer)
{
	struct attribute * attr = to_attr(dentry);
	struct kobject * kobj = to_kobj(dentry->d_parent);
	struct sysfs_ops * ops = buffer->ops;
	int ret = 0;
	ssize_t count;

	if (!buffer->page)
		buffer->page = (char *) get_zeroed_page(GFP_KERNEL);
	if (!buffer->page)
		return -ENOMEM;

	count = ops->show(kobj,attr,buffer->page);
	buffer->needs_read_fill = 0;
	BUG_ON(count > (ssize_t)PAGE_SIZE);
	if (count >= 0)
		buffer->count = count;
	else
		ret = count;
	return ret;
}

static int flush_read_buffer(struct sysfs_buffer * buffer, char __user * buf,
			     size_t count, loff_t * ppos)
{
	int error;

	if (*ppos > buffer->count)
		return 0;

	if (count > (buffer->count - *ppos))
		count = buffer->count - *ppos;

	error = copy_to_user(buf, buffer->page + *ppos,count);
	if (!error)
		*ppos += count;
	return error ? -EFAULT : count;
}

static ssize_t
sysfs_read_file(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    struct sysfs_buffer * buffer = file->private_data;
	ssize_t retval = 0;

	down(&buffer->sem);
	if (buffer->needs_read_fill) {
		if ((retval = fill_read_buffer(file->f_dentry, buffer)))
			goto out;
	}
	pr_debug("%s: count = %d, ppos = %lld, buf = %s\n",
		 __FUNCTION__,count,*ppos,buffer->page);
	retval = flush_read_buffer(buffer,buf,count,ppos);
out:
	up(&buffer->sem);
	return retval;
}

static ssize_t
sysfs_write_file(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	panic("in sysfs_write_file");
	return 0;
}

static int check_perm(struct inode * inode, struct file * file)
{
	struct kobject *kobj = sysfs_get_kobject(file->f_dentry->d_parent);
	struct attribute * attr = to_attr(file->f_dentry);
	struct sysfs_buffer * buffer;
	struct sysfs_ops * ops = NULL;
	int error = 0;

	if (!kobj || !attr)
		goto Einval;

	/* Grab the module reference for this attribute if we have one */
	if (!try_module_get(attr->owner)) {
		error = -ENODEV;
		goto Done;
	}

	/* if the kobject has no ktype, then we assume that it is a subsystem
	 * itself, and use ops for it.
	 */
	if (kobj->kset && kobj->kset->ktype)
		ops = kobj->kset->ktype->sysfs_ops;
	else if (kobj->ktype)
		ops = kobj->ktype->sysfs_ops;
	else
		ops = &subsys_sysfs_ops;

	/* No sysfs operations, either from having no subsystem,
	 * or the subsystem have no operations.
	 */
	if (!ops)
		goto Eaccess;

	/* File needs write support.
	 * The inode's perms must say it's ok, 
	 * and we must have a store method.
	 */
	if (file->f_mode & FMODE_WRITE) {

		if (!(inode->i_mode & S_IWUGO) || !ops->store)
			goto Eaccess;

	}

	/* File needs read support.
	 * The inode's perms must say it's ok, and we there
	 * must be a show method for it.
	 */
	if (file->f_mode & FMODE_READ) {
		if (!(inode->i_mode & S_IRUGO) || !ops->show)
			goto Eaccess;
	}

	/* No error? Great, allocate a buffer for the file, and store it
	 * it in file->private_data for easy access.
	 */
	buffer = kmalloc(sizeof(struct sysfs_buffer),GFP_KERNEL);
	if (buffer) {
		memset(buffer,0,sizeof(struct sysfs_buffer));
		init_MUTEX(&buffer->sem);
		buffer->needs_read_fill = 1;
		buffer->ops = ops;
		file->private_data = buffer;
	} else
		error = -ENOMEM;
	goto Done;

 Einval:
	error = -EINVAL;
	goto Done;
 Eaccess:
	error = -EACCES;
	module_put(attr->owner);
 Done:
	if (error && kobj)
		kobject_put(kobj);
	return error;
}

static int sysfs_open_file(struct inode * inode, struct file * filp)
{
    return check_perm(inode, filp);
}

static int sysfs_release(struct inode * inode, struct file * filp)
{
    struct kobject * kobj = to_kobj(filp->f_dentry->d_parent);
	struct attribute * attr = to_attr(filp->f_dentry);
	struct module * owner = attr->owner;
	struct sysfs_buffer * buffer = filp->private_data;

	if (kobj) 
		kobject_put(kobj);
	/* After this point, attr should not be accessed. */
	module_put(owner);

	if (buffer) {
		if (buffer->page)
			free_page((unsigned long)buffer->page);
		kfree(buffer);
	}
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