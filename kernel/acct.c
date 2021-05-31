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

int acct_parm[3] = {4, 2, 30};
#define RESUME		(acct_parm[0])	/* >foo% free space - resume */
#define SUSPEND		(acct_parm[1])	/* <foo% free space - suspend */
#define ACCT_TIMEOUT	(acct_parm[2])	/* foo second timeout between checks */

struct acct_glbs {
	spinlock_t		lock;
	volatile int		active;
	volatile int		needcheck;
	struct file		*file;
	struct timer_list	timer;
};

static struct acct_glbs acct_globals __cacheline_aligned = {SPIN_LOCK_UNLOCKED};

static void acct_timeout(unsigned long unused)
{
	acct_globals.needcheck = 1;
}

static int check_free_space(struct file *file)
{
	struct kstatfs sbuf;
	int res;
	int act;
	sector_t resume;
	sector_t suspend;

	spin_lock(&acct_globals.lock);
	res = acct_globals.active;
	if (!file || !acct_globals.needcheck)
		goto out;
	spin_unlock(&acct_globals.lock);

	/* May block */
	if (vfs_statfs(file->f_dentry->d_inode->i_sb, &sbuf))
		return res;
	suspend = sbuf.f_blocks * SUSPEND;
	resume = sbuf.f_blocks * RESUME;

	sector_div(suspend, 100);
	sector_div(resume, 100);

	if (sbuf.f_bavail <= suspend)
		act = -1;
	else if (sbuf.f_bavail >= resume)
		act = 1;
	else
		act = 0;

	/*
	 * If some joker switched acct_globals.file under us we'ld better be
	 * silent and _not_ touch anything.
	 */
	spin_lock(&acct_globals.lock);
	if (file != acct_globals.file) {
		if (act)
			res = act>0;
		goto out;
	}

	if (acct_globals.active) {
		if (act < 0) {
			acct_globals.active = 0;
			printk(KERN_INFO "Process accounting paused\n");
		}
	} else {
		if (act > 0) {
			acct_globals.active = 1;
			printk(KERN_INFO "Process accounting resumed\n");
		}
	}

	del_timer(&acct_globals.timer);
	acct_globals.needcheck = 0;
	acct_globals.timer.expires = jiffies + ACCT_TIMEOUT*HZ;
	add_timer(&acct_globals.timer);
	res = acct_globals.active;
out:
	spin_unlock(&acct_globals.lock);
	return res;
}

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

#define	MANTSIZE	13			/* 13 bit mantissa. */
#define	EXPSIZE		3			/* Base 8 (3 bit) exponent. */
#define	MAXFRACT	((1 << MANTSIZE) - 1)	/* Maximum fractional value. */

static comp_t encode_comp_t(unsigned long value)
{
	int exp, rnd;

	exp = rnd = 0;
	while (value > MAXFRACT) {
		rnd = value & (1 << (EXPSIZE - 1));	/* Round up? */
		value >>= EXPSIZE;	/* Base 8 exponent == 3 bit shift. */
		exp++;
	}

	/*
         * If we need to round up, do it (and handle overflow correctly).
         */
	if (rnd && (++value > MAXFRACT)) {
		value >>= EXPSIZE;
		exp++;
	}

	/*
         * Clean it up and polish it off.
         */
	exp <<= MANTSIZE;		/* Shift the exponent into place */
	exp += value;			/* and add on the mantissa. */
	return exp;
}

#if ACCT_VERSION==3
/*
 * encode an u64 into a 32 bit IEEE float
 */
static u32 encode_float(u64 value)
{
	unsigned exp = 190;
	unsigned u;

	if (value==0) return 0;
	while ((s64)value > 0){
		value <<= 1;
		exp--;
	}
	u = (u32)(value >> 40) & 0x7fffffu;
	return u | (exp << 23);
}
#endif

static void do_acct_process(long exitcode, struct file *file)
{
	acct_t ac;
	mm_segment_t fs;
	unsigned long vsize;
	unsigned long flim;
	u64 elapsed;
	u64 run_time;
	struct timespec uptime;

	/*
	 * First check to see if there is enough free_space to continue
	 * the process accounting system.
	 */
	if (!check_free_space(file))
		return;

	/*
	 * Fill the accounting struct with the needed info as recorded
	 * by the different kernel functions.
	 */
	memset((caddr_t)&ac, 0, sizeof(acct_t));

	ac.ac_version = ACCT_VERSION | ACCT_BYTEORDER;
	strlcpy(ac.ac_comm, current->comm, sizeof(ac.ac_comm));

	/* calculate run_time in nsec*/
	do_posix_clock_monotonic_gettime(&uptime);
	run_time = (u64)uptime.tv_sec*NSEC_PER_SEC + uptime.tv_nsec;
	run_time -= (u64)current->start_time.tv_sec*NSEC_PER_SEC
					+ current->start_time.tv_nsec;
	/* convert nsec -> AHZ */
	elapsed = nsec_to_AHZ(run_time);
#if ACCT_VERSION==3
	ac.ac_etime = encode_float(elapsed);
#else
	ac.ac_etime = encode_comp_t(elapsed < (unsigned long) -1l ?
	                       (unsigned long) elapsed : (unsigned long) -1l);
#endif
#if ACCT_VERSION==1 || ACCT_VERSION==2
	{
		/* new enlarged etime field */
		comp2_t etime = encode_comp2_t(elapsed);
		ac.ac_etime_hi = etime >> 16;
		ac.ac_etime_lo = (u16) etime;
	}
#endif
	do_div(elapsed, AHZ);
	ac.ac_btime = xtime.tv_sec - elapsed;
	ac.ac_utime = encode_comp_t(jiffies_to_AHZ(
					    current->signal->utime +
					    current->group_leader->utime));
	ac.ac_stime = encode_comp_t(jiffies_to_AHZ(
					    current->signal->stime +
					    current->group_leader->stime));
	/* we really need to bite the bullet and change layout */
	ac.ac_uid = current->uid;
	ac.ac_gid = current->gid;
#if ACCT_VERSION==2
	ac.ac_ahz = AHZ;
#endif
#if ACCT_VERSION==1 || ACCT_VERSION==2
	/* backward-compatible 16 bit fields */
	ac.ac_uid16 = current->uid;
	ac.ac_gid16 = current->gid;
#endif
#if ACCT_VERSION==3
	ac.ac_pid = current->tgid;
	ac.ac_ppid = current->parent->tgid;
#endif

	read_lock(&tasklist_lock);	/* pin current->signal */
	ac.ac_tty = current->signal->tty ?
		old_encode_dev(tty_devnum(current->signal->tty)) : 0;
	read_unlock(&tasklist_lock);

	ac.ac_flag = 0;
	if (current->flags & PF_FORKNOEXEC)
		ac.ac_flag |= AFORK;
	if (current->flags & PF_SUPERPRIV)
		ac.ac_flag |= ASU;
	if (current->flags & PF_DUMPCORE)
		ac.ac_flag |= ACORE;
	if (current->flags & PF_SIGNALED)
		ac.ac_flag |= AXSIG;

	vsize = 0;
	if (current->mm) {
		struct vm_area_struct *vma;
		down_read(&current->mm->mmap_sem);
		vma = current->mm->mmap;
		while (vma) {
			vsize += vma->vm_end - vma->vm_start;
			vma = vma->vm_next;
		}
		up_read(&current->mm->mmap_sem);
	}
	vsize = vsize / 1024;
	ac.ac_mem = encode_comp_t(vsize);
	ac.ac_io = encode_comp_t(0 /* current->io_usage */);	/* %% */
	ac.ac_rw = encode_comp_t(ac.ac_io / 1024);
	ac.ac_minflt = encode_comp_t(current->signal->min_flt +
				     current->group_leader->min_flt);
	ac.ac_majflt = encode_comp_t(current->signal->maj_flt +
				     current->group_leader->maj_flt);
	ac.ac_swaps = encode_comp_t(0);
	ac.ac_exitcode = exitcode;

	/*
         * Kernel segment override to datasegment and write it
         * to the accounting file.
         */
	fs = get_fs();
	set_fs(KERNEL_DS);
	/*
 	 * Accounting records are not subject to resource limits.
 	 */
	flim = current->signal->rlim[RLIMIT_FSIZE].rlim_cur;
	current->signal->rlim[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
	file->f_op->write(file, (char *)&ac,
			       sizeof(acct_t), &file->f_pos);
	current->signal->rlim[RLIMIT_FSIZE].rlim_cur = flim;
	set_fs(fs);
}

void acct_process(long exitcode)
{
	struct file *file = NULL;

	/*
	 * accelerate the common fastpath:
	 */
	if (!acct_globals.file)
		return;

	spin_lock(&acct_globals.lock);
	file = acct_globals.file;
	if (unlikely(!file)) {
		spin_unlock(&acct_globals.lock);
		return;
	}
	get_file(file);
	spin_unlock(&acct_globals.lock);

	do_acct_process(exitcode, file);
	fput(file);
}

/*
 * acct_update_integrals
 *    -  update mm integral fields in task_struct
 */
void acct_update_integrals(void)
{
	struct task_struct *tsk = current;

	if (likely(tsk->mm)) {
		long delta = tsk->stime - tsk->acct_stimexpd;

		if (delta == 0)
			return;
		tsk->acct_stimexpd = tsk->stime;
		tsk->acct_rss_mem1 += delta * tsk->mm->rss;
		tsk->acct_vm_mem1 += delta * tsk->mm->total_vm;
	}
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