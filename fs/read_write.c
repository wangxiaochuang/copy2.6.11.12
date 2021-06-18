#include <linux/slab.h> 
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/smp_lock.h>
#include <linux/dnotify.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/syscalls.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

loff_t generic_file_llseek(struct file *file, loff_t offset, int origin)
{
    long long retval;
	struct inode *inode = file->f_mapping->host;

	down(&inode->i_sem);
	switch (origin) {
		case 2:
			offset += inode->i_size;
			break;
		case 1:
			offset += file->f_pos;
	}
	retval = -EINVAL;
	if (offset>=0 && offset<=inode->i_sb->s_maxbytes) {
		if (offset != file->f_pos) {
			file->f_pos = offset;
			file->f_version = 0;
		}
		retval = offset;
	}
	up(&inode->i_sem);
	return retval;
}

EXPORT_SYMBOL(generic_file_llseek);

loff_t no_llseek(struct file *file, loff_t offset, int origin)
{
	return -ESPIPE;
}
EXPORT_SYMBOL(no_llseek);

loff_t default_llseek(struct file *file, loff_t offset, int origin)
{
	long long retval;

	lock_kernel();
	switch (origin) {
		case 2:
			offset += i_size_read(file->f_dentry->d_inode);
			break;
		case 1:
			offset += file->f_pos;
	}
	retval = -EINVAL;
	if (offset >= 0) {
		if (offset != file->f_pos) {
			file->f_pos = offset;
			file->f_version = 0;
		}
		retval = offset;
	}
	unlock_kernel();
	return retval;
}
EXPORT_SYMBOL(default_llseek);

loff_t vfs_llseek(struct file *file, loff_t offset, int origin)
{
	loff_t (*fn)(struct file *, loff_t, int);

	fn = no_llseek;
	if (file->f_mode & FMODE_LSEEK) {
		fn = default_llseek;
		if (file->f_op && file->f_op->llseek)
			fn = file->f_op->llseek;
	}
	return fn(file, offset, origin);
}
EXPORT_SYMBOL(vfs_llseek);

asmlinkage off_t sys_lseek(unsigned int fd, off_t offset, unsigned int origin)
{
	panic("in sys_lseek");
	return 0;
}

#ifdef __ARCH_WANT_SYS_LLSEEK
asmlinkage long sys_llseek(unsigned int fd, unsigned long offset_high,
			   unsigned long offset_low, loff_t __user * result,
			   unsigned int origin)
{
	panic("in sys_llseek");
	return 0;
}
#endif

int rw_verify_area(int read_write, struct file *file, loff_t *ppos, size_t count)
{
	struct inode *inode;
	loff_t pos;

	if (unlikely(count > file->f_maxcount))
		goto Einval;
    pos = *ppos;
    if (unlikely((pos < 0) || (loff_t) (pos + count) < 0))
		goto Einval;
    
    inode = file->f_dentry->d_inode;
	if (inode->i_flock && MANDATORY_LOCK(inode))
		return locks_mandatory_area(read_write == READ ? FLOCK_VERIFY_READ : FLOCK_VERIFY_WRITE, inode, file, pos, count);
	return 0;

Einval:
	return -EINVAL;
}


ssize_t do_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
    struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;
	ret = filp->f_op->aio_read(&kiocb, buf, len, kiocb.ki_pos);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	*ppos = kiocb.ki_pos;
	return ret;
}

EXPORT_SYMBOL(do_sync_read);

ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!file->f_op || (!file->f_op->read && !file->f_op->aio_read))
		return -EINVAL;
	if (unlikely(!access_ok(VERIFY_WRITE, buf, count)))
		return -EFAULT;

	ret = rw_verify_area(READ, file, pos, count);
	if (!ret) {
		ret = security_file_permission (file, MAY_READ);
		if (!ret) {
			if (file->f_op->read)
				ret = file->f_op->read(file, buf, count, pos);
			else
				ret = do_sync_read(file, buf, count, pos);
			if (ret > 0) {
				dnotify_parent(file->f_dentry, DN_ACCESS);
				current->rchar += ret;
			}
			current->syscr++;
		}
	}

	return ret;
}

EXPORT_SYMBOL(vfs_read);

ssize_t do_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
    struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;
	ret = filp->f_op->aio_write(&kiocb, buf, len, kiocb.ki_pos);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	*ppos = kiocb.ki_pos;
	return ret;
}

EXPORT_SYMBOL(do_sync_write);

ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

    if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!file->f_op || (!file->f_op->write && !file->f_op->aio_write))
		return -EINVAL;
	if (unlikely(!access_ok(VERIFY_READ, buf, count)))
		return -EFAULT;

    ret = rw_verify_area(WRITE, file, pos, count);
	if (!ret) {
		ret = security_file_permission (file, MAY_WRITE);
		if (!ret) {
			if (file->f_op->write)
				ret = file->f_op->write(file, buf, count, pos);
			else
				ret = do_sync_write(file, buf, count, pos);
			if (ret > 0) {
				dnotify_parent(file->f_dentry, DN_MODIFY);
				current->wchar += ret;
			}
			current->syscw++;
		}
	}

	return ret;
}

EXPORT_SYMBOL(vfs_write);

static inline loff_t file_pos_read(struct file *file)
{
	return file->f_pos;
}

static inline void file_pos_write(struct file *file, loff_t pos)
{
	file->f_pos = pos;
}

asmlinkage ssize_t sys_read(unsigned int fd, char __user * buf, size_t count)
{
	struct file *file;
	ssize_t ret = -EBADF;
	int fput_needed;

	file = fget_light(fd, &fput_needed);
	if (file) {
		loff_t pos = file_pos_read(file);
		ret = vfs_read(file, buf, count, &pos);
		file_pos_write(file, pos);
		fput_light(file, fput_needed);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(sys_read);

asmlinkage ssize_t sys_write(unsigned int fd, const char __user * buf, size_t count)
{
    struct file *file;
	ssize_t ret = -EBADF;
	int fput_needed;

	file = fget_light(fd, &fput_needed);
	if (file) {
        loff_t pos = file_pos_read(file);
        ret = vfs_write(file, buf, count, &pos);
        file_pos_write(file, pos);
        fput_light(file, fput_needed);
    }

    return ret;
}