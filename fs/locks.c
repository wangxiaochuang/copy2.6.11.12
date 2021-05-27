#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/syscalls.h>
#include <linux/time.h>

#include <asm/semaphore.h>
#include <asm/uaccess.h>

#define IS_POSIX(fl)	(fl->fl_flags & FL_POSIX)
#define IS_FLOCK(fl)	(fl->fl_flags & FL_FLOCK)
#define IS_LEASE(fl)	(fl->fl_flags & FL_LEASE)

static int assign_type(struct file_lock *fl, int type)
{
	switch (type) {
	case F_RDLCK:
	case F_WRLCK:
	case F_UNLCK:
		fl->fl_type = type;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void locks_wake_up_blocks(struct file_lock *blocker)
{
    panic("in locks_wake_up_blocks function");
}

/*
 * Delete a lock and then free it.
 * Wake up processes that are blocked waiting for this lock,
 * notify the FS that the lock has been cleared and
 * finally free the lock.
 */
static void locks_delete_lock(struct file_lock **thisfl_p)
{
    panic("in locks_delete_lock function");
}

int locks_mandatory_locked(struct inode *inode)
{
    panic("in locks_mandatory_locked function");
    return 0;
}

int locks_mandatory_area(int read_write, struct inode *inode,
			 struct file *filp, loff_t offset,
			 size_t count)
{
    panic("in locks_mandatory_area function");
    return 0;
}

EXPORT_SYMBOL(locks_mandatory_area);

/* We already had a lease on this file; just change its type */
static int lease_modify(struct file_lock **before, int arg)
{
	struct file_lock *fl = *before;
	int error = assign_type(fl, arg);

	if (error)
		return error;
	locks_wake_up_blocks(fl);
	if (arg == F_UNLCK)
		locks_delete_lock(before);
	return 0;
}

int __break_lease(struct inode *inode, unsigned int mode)
{
    panic("in __break_lease function");
    return 0;
}

void locks_remove_posix(struct file *filp, fl_owner_t owner)
{
    panic("in locks_remove_posix function");
}

EXPORT_SYMBOL(locks_remove_posix);

/*
 * This function is called on the last close of an open file.
 */
void locks_remove_flock(struct file *filp)
{
    struct inode * inode = filp->f_dentry->d_inode; 
	struct file_lock *fl;
	struct file_lock **before;

	if (!inode->i_flock)
		return;

    if (filp->f_op && filp->f_op->flock) {
		struct file_lock fl = { .fl_flags = FL_FLOCK,
					.fl_type = F_UNLCK };
		filp->f_op->flock(filp, F_SETLKW, &fl);
	}

    lock_kernel();
	before = &inode->i_flock;

    while ((fl = *before) != NULL) {
        if (fl->fl_file == filp) {
            /*
			 * We might have a POSIX lock that was created at the same time
			 * the filp was closed for the last time. Just remove that too,
			 * regardless of ownership, since nobody can own it.
			 */
			if (IS_FLOCK(fl) || IS_POSIX(fl)) {
				locks_delete_lock(before);
				continue;
			}
			if (IS_LEASE(fl)) {
				lease_modify(before, F_UNLCK);
				continue;
			}
			/* What? */
			BUG();
        }
        before = &fl->fl_next;
    }
    unlock_kernel();
}