#include <linux/config.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/acct.h>
#include <linux/file.h>
#include <linux/tty.h>
#include <linux/security.h>
#include <linux/vfs.h>
#include <linux/jiffies.h>
#include <linux/times.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>
#include <asm/div64.h>
#include <linux/blkdev.h> /* sector_div */

struct acct_glbs {
	spinlock_t		lock;
	volatile int		active;
	volatile int		needcheck;
	struct file		*file;
	struct timer_list	timer;
};

static struct acct_glbs acct_globals __cacheline_aligned = {SPIN_LOCK_UNLOCKED};

void acct_file_reopen(struct file *file)
{
    panic("in acct_file_reopen function");
}

void acct_auto_close(struct super_block *sb)
{
	spin_lock(&acct_globals.lock);
	if (acct_globals.file &&
	    acct_globals.file->f_dentry->d_inode->i_sb == sb) {
		acct_file_reopen((struct file *)NULL);
	}
	spin_unlock(&acct_globals.lock);
}

/*
 * acct_clear_integrals
 *    - clear the mm integral fields in task_struct
 */
void acct_clear_integrals(struct task_struct *tsk)
{
	if (tsk) {
		tsk->acct_stimexpd = 0;
		tsk->acct_rss_mem1 = 0;
		tsk->acct_vm_mem1 = 0;
	}
}