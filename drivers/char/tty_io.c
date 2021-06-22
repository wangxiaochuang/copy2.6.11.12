#include <linux/config.h>
#include <linux/types.h>
#include <linux/major.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#include <linux/devpts_fs.h>
#include <linux/file.h>
#include <linux/console.h>
#include <linux/timer.h>
#include <linux/ctype.h>
#include <linux/kd.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/wait.h>
#include <linux/bitops.h>

#include <asm/uaccess.h>
#include <asm/system.h>

#include <linux/kbd_kern.h>
#include <linux/vt_kern.h>
#include <linux/selection.h>
#include <linux/devfs_fs_kernel.h>

#include <linux/kmod.h>

#undef TTY_DEBUG_HANGUP

#define TTY_PARANOIA_CHECK 1
#define CHECK_TTY_COUNT 1

struct termios tty_std_termios = {	/* for the benefit of tty drivers  */
	.c_iflag = ICRNL | IXON,
	.c_oflag = OPOST | ONLCR,
	.c_cflag = B38400 | CS8 | CREAD | HUPCL,
	.c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK |
		   ECHOCTL | ECHOKE | IEXTEN,
	.c_cc = INIT_C_CC
};

EXPORT_SYMBOL(tty_std_termios);

/* This list gets poked at by procfs and various bits of boot up code. This
   could do with some rationalisation such as pulling the tty proc function
   into this file */
   
LIST_HEAD(tty_drivers);			/* linked list of tty drivers */


/* Semaphore to protect creating and releasing a tty. This is shared with
   vt.c for deeply disgusting hack reasons */
DECLARE_MUTEX(tty_sem);

#ifdef CONFIG_UNIX98_PTYS
extern struct tty_driver *ptm_driver;	/* Unix98 pty masters; for /dev/ptmx */
extern int pty_limit;		/* Config limit on Unix98 ptys */
static DEFINE_IDR(allocated_ptys);
static DECLARE_MUTEX(allocated_ptys_lock);
static int ptmx_open(struct inode *, struct file *);
#endif

extern void disable_early_printk(void);

static void initialize_tty_struct(struct tty_struct *tty);

static ssize_t tty_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t tty_write(struct file *, const char __user *, size_t, loff_t *);
ssize_t redirected_tty_write(struct file *, const char __user *, size_t, loff_t *);
static unsigned int tty_poll(struct file *, poll_table *);
static int tty_open(struct inode *, struct file *);
static int tty_release(struct inode *, struct file *);
int tty_ioctl(struct inode * inode, struct file * file,
	      unsigned int cmd, unsigned long arg);
static int tty_fasync(int fd, struct file * filp, int on);
extern void rs_360_init(void);
static void release_mem(struct tty_struct *tty, int idx);


static struct tty_struct *alloc_tty_struct(void)
{
	struct tty_struct *tty;

	tty = kmalloc(sizeof(struct tty_struct), GFP_KERNEL);
	if (tty)
		memset(tty, 0, sizeof(struct tty_struct));
	return tty;
}

static inline void free_tty_struct(struct tty_struct *tty)
{
	kfree(tty->write_buf);
	kfree(tty);
}

#define TTY_NUMBER(tty) ((tty)->index + (tty)->driver->name_base)

char *tty_name(struct tty_struct *tty, char *buf)
{
	if (!tty) /* Hmm.  NULL pointer.  That's fun. */
		strcpy(buf, "NULL tty");
	else
		strcpy(buf, tty->name);
	return buf;
}

EXPORT_SYMBOL(tty_name);

inline int tty_paranoia_check(struct tty_struct *tty, struct inode *inode,
			      const char *routine)
{
	panic("in tty_paranoia_check");
	return 0;
}

static int check_tty_count(struct tty_struct *tty, const char *routine)
{
#ifdef CHECK_TTY_COUNT
	struct list_head *p;
	int count = 0;
	
	file_list_lock();
	list_for_each(p, &tty->tty_files) {
		count++;
	}
	file_list_unlock();
	if (tty->driver->type == TTY_DRIVER_TYPE_PTY &&
	    tty->driver->subtype == PTY_TYPE_SLAVE &&
	    tty->link && tty->link->count)
		count++;
	if (tty->count != count) {
		printk(KERN_WARNING "Warning: dev (%s) tty->count(%d) "
				    "!= #fd's(%d) in %s\n",
		       tty->name, tty->count, count, routine);
		return count;
       }	
#endif
	return 0;
}

static void tty_set_termios_ldisc(struct tty_struct *tty, int num)
{
	down(&tty->termios_sem);
	tty->termios->c_line = num;
	up(&tty->termios_sem);
}

/*
 *	This guards the refcounted line discipline lists. The lock
 *	must be taken with irqs off because there are hangup path
 *	callers who will do ldisc lookups and cannot sleep.
 */
 
static DEFINE_SPINLOCK(tty_ldisc_lock);
static DECLARE_WAIT_QUEUE_HEAD(tty_ldisc_wait);
static struct tty_ldisc tty_ldiscs[NR_LDISCS];	/* line disc dispatch table	*/

int tty_register_ldisc(int disc, struct tty_ldisc *new_ldisc) {
    unsigned long flags;
	int ret = 0;
	
	if (disc < N_TTY || disc >= NR_LDISCS)
		return -EINVAL;

    spin_lock_irqsave(&tty_ldisc_lock, flags);
    if (new_ldisc) {
        tty_ldiscs[disc] = *new_ldisc;
        tty_ldiscs[disc].num = disc;
		tty_ldiscs[disc].flags |= LDISC_FLAG_DEFINED;
		tty_ldiscs[disc].refcount = 0;
    } else {
        if(tty_ldiscs[disc].refcount)
			ret = -EBUSY;
		else
			tty_ldiscs[disc].flags &= ~LDISC_FLAG_DEFINED;
    }
    spin_unlock_irqrestore(&tty_ldisc_lock, flags);
	
	return ret;
}

EXPORT_SYMBOL(tty_register_ldisc);

struct tty_ldisc *tty_ldisc_get(int disc)
{
	unsigned long flags;
	struct tty_ldisc *ld;

	if (disc < N_TTY || disc >= NR_LDISCS)
		return NULL;
	
	spin_lock_irqsave(&tty_ldisc_lock, flags);

	ld = &tty_ldiscs[disc];
	/* Check the entry is defined */
	if(ld->flags & LDISC_FLAG_DEFINED)
	{
		/* If the module is being unloaded we can't use it */
		if (!try_module_get(ld->owner))
		       	ld = NULL;
		else /* lock it */
			ld->refcount++;
	}
	else
		ld = NULL;
	spin_unlock_irqrestore(&tty_ldisc_lock, flags);
	return ld;
}

EXPORT_SYMBOL_GPL(tty_ldisc_get);

void tty_ldisc_put(int disc)
{
	struct tty_ldisc *ld;
	unsigned long flags;
	
	if (disc < N_TTY || disc >= NR_LDISCS)
		BUG();
		
	spin_lock_irqsave(&tty_ldisc_lock, flags);
	ld = &tty_ldiscs[disc];
	if(ld->refcount == 0)
		BUG();
	ld->refcount --;
	module_put(ld->owner);
	spin_unlock_irqrestore(&tty_ldisc_lock, flags);
}
	
EXPORT_SYMBOL_GPL(tty_ldisc_put);

static void tty_ldisc_assign(struct tty_struct *tty, struct tty_ldisc *ld)
{
	tty->ldisc = *ld;
	tty->ldisc.refcount = 0;
}

static int tty_ldisc_try(struct tty_struct *tty)
{
	unsigned long flags;
	struct tty_ldisc *ld;
	int ret = 0;
	
	spin_lock_irqsave(&tty_ldisc_lock, flags);
	ld = &tty->ldisc;
	if(test_bit(TTY_LDISC, &tty->flags))
	{
		ld->refcount++;
		ret = 1;
	}
	spin_unlock_irqrestore(&tty_ldisc_lock, flags);
	return ret;
}

struct tty_ldisc *tty_ldisc_ref_wait(struct tty_struct *tty)
{
	/* wait_event is a macro */
	wait_event(tty_ldisc_wait, tty_ldisc_try(tty));
	if(tty->ldisc.refcount == 0)
		printk(KERN_ERR "tty_ldisc_ref_wait\n");
	return &tty->ldisc;
}

EXPORT_SYMBOL_GPL(tty_ldisc_ref_wait);

struct tty_ldisc *tty_ldisc_ref(struct tty_struct *tty)
{
	if(tty_ldisc_try(tty))
		return &tty->ldisc;
	return NULL;
}

EXPORT_SYMBOL_GPL(tty_ldisc_ref);

void tty_ldisc_deref(struct tty_ldisc *ld)
{
	unsigned long flags;

	if(ld == NULL)
		BUG();
		
	spin_lock_irqsave(&tty_ldisc_lock, flags);
	if(ld->refcount == 0)
		printk(KERN_ERR "tty_ldisc_deref: no references.\n");
	else
		ld->refcount--;
	if(ld->refcount == 0)
		wake_up(&tty_ldisc_wait);
	spin_unlock_irqrestore(&tty_ldisc_lock, flags);
}

EXPORT_SYMBOL_GPL(tty_ldisc_deref);

static void tty_ldisc_enable(struct tty_struct *tty)
{
	set_bit(TTY_LDISC, &tty->flags);
	wake_up(&tty_ldisc_wait);
}

static int tty_set_ldisc(struct tty_struct *tty, int ldisc)
{
	panic("in tty_set_ldisc");
	return 0;
}

static struct tty_driver *get_tty_driver(dev_t device, int *index)
{
    struct tty_driver *p;

	list_for_each_entry(p, &tty_drivers, tty_drivers) {
		dev_t base = MKDEV(p->major, p->minor_start);
		if (device < base || device >= base + p->num)
			continue;
		*index = device - base;
		return p;
	}
	return NULL;
}

int tty_check_change(struct tty_struct * tty)
{
	if (current->signal->tty != tty)
		return 0;
	if (tty->pgrp <= 0) {
		printk(KERN_WARNING "tty_check_change: tty->pgrp <= 0!\n");
		return 0;
	}
	if (process_group(current) == tty->pgrp)
		return 0;
	if (is_ignored(SIGTTOU))
		return 0;
	if (is_orphaned_pgrp(process_group(current)))
		return -EIO;
	(void) kill_pg(process_group(current), SIGTTOU, 1);
	return -ERESTARTSYS;
}

EXPORT_SYMBOL(tty_check_change);

static ssize_t hung_up_tty_read(struct file * file, char __user * buf,
				size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t hung_up_tty_write(struct file * file, const char __user * buf,
				 size_t count, loff_t *ppos)
{
	return -EIO;
}

/* No kernel lock held - none needed ;) */
static unsigned int hung_up_tty_poll(struct file * filp, poll_table * wait)
{
	return POLLIN | POLLOUT | POLLERR | POLLHUP | POLLRDNORM | POLLWRNORM;
}

static int hung_up_tty_ioctl(struct inode * inode, struct file * file,
			     unsigned int cmd, unsigned long arg)
{
	return cmd == TIOCSPGRP ? -ENOTTY : -EIO;
}

static struct file_operations tty_fops = {
	.llseek		= no_llseek,
	.read		= tty_read,
	.write		= tty_write,
	.poll		= tty_poll,
	.ioctl		= tty_ioctl,
	.open		= tty_open,
	.release	= tty_release,
	.fasync		= tty_fasync,
};

#ifdef CONFIG_UNIX98_PTYS
static struct file_operations ptmx_fops = {
	.llseek		= no_llseek,
	.read		= tty_read,
	.write		= tty_write,
	.poll		= tty_poll,
	.ioctl		= tty_ioctl,
	.open		= ptmx_open,
	.release	= tty_release,
	.fasync		= tty_fasync,
};
#endif

static struct file_operations console_fops = {
	.llseek		= no_llseek,
	.read		= tty_read,
	.write		= redirected_tty_write,
	.poll		= tty_poll,
	.ioctl		= tty_ioctl,
	.open		= tty_open,
	.release	= tty_release,
	.fasync		= tty_fasync,
};

static struct file_operations hung_up_tty_fops = {
	.llseek		= no_llseek,
	.read		= hung_up_tty_read,
	.write		= hung_up_tty_write,
	.poll		= hung_up_tty_poll,
	.ioctl		= hung_up_tty_ioctl,
	.release	= tty_release,
};

static DEFINE_SPINLOCK(redirect_lock);
static struct file *redirect;

void tty_wakeup(struct tty_struct *tty)
{
    panic("in tty_wakeup");
}

EXPORT_SYMBOL_GPL(tty_wakeup);

void tty_ldisc_flush(struct tty_struct *tty)
{
    panic("in tty_ldisc_flush");
}

EXPORT_SYMBOL_GPL(tty_ldisc_flush);


static void do_tty_hangup(void *data)
{
    panic("in do_tty_hangup");
}

void tty_hangup(struct tty_struct * tty)
{
#ifdef TTY_DEBUG_HANGUP
	char	buf[64];
	
	printk(KERN_DEBUG "%s hangup...\n", tty_name(tty, buf));
#endif
	schedule_work(&tty->hangup_work);
}

EXPORT_SYMBOL(tty_hangup);

void tty_vhangup(struct tty_struct * tty)
{
#ifdef TTY_DEBUG_HANGUP
	char	buf[64];

	printk(KERN_DEBUG "%s vhangup...\n", tty_name(tty, buf));
#endif
	do_tty_hangup((void *) tty);
}
EXPORT_SYMBOL(tty_vhangup);

int tty_hung_up_p(struct file * filp)
{
	return (filp->f_op == &hung_up_tty_fops);
}

EXPORT_SYMBOL(tty_hung_up_p);

void disassociate_ctty(int on_exit)     // p 913
{
    panic("in disassociate_ctty function");
}

void stop_tty(struct tty_struct *tty)
{
    panic("in stop_tty");
}

EXPORT_SYMBOL(stop_tty);

void start_tty(struct tty_struct *tty)
{
    panic("in start_tty");
}

EXPORT_SYMBOL(start_tty);

static ssize_t tty_read(struct file * file, char __user * buf, size_t count, 
			loff_t *ppos)
{
    panic("in tty_read");
    return 0;
}

static inline ssize_t do_tty_write(
	ssize_t (*write)(struct tty_struct *, struct file *, const unsigned char *, size_t),
	struct tty_struct *tty,
	struct file *file,
	const char __user *buf,
	size_t count)
{
    panic("in do_tty_write");
    return 0;
}

static ssize_t tty_write(struct file * file, const char __user * buf, size_t count,
			 loff_t *ppos)
{
    panic("in tty_write");
    return 0;
}

ssize_t redirected_tty_write(struct file * file, const char __user * buf, size_t count,
			 loff_t *ppos)
{
    panic("in redirected_tty_write");
    return 0;
}

static char ptychar[] = "pqrstuvwxyzabcde";

static inline void pty_line_name(struct tty_driver *driver, int index, char *p)
{
	int i = index + driver->name_base;
	/* ->name is initialized to "ttyp", but "tty" is expected */
	sprintf(p, "%s%c%x",
			driver->subtype == PTY_TYPE_SLAVE ? "tty" : driver->name,
			ptychar[i >> 4 & 0xf], i & 0xf);
}

static inline void tty_line_name(struct tty_driver *driver, int index, char *p)
{
	sprintf(p, "%s%d", driver->name, index + driver->name_base);
}

static int init_dev(struct tty_driver *driver, int idx,
	struct tty_struct **ret_tty)
{
    struct tty_struct *tty, *o_tty;
	struct termios *tp, **tp_loc, *o_tp, **o_tp_loc;
	struct termios *ltp, **ltp_loc, *o_ltp, **o_ltp_loc;
	int retval = 0;

	if (driver->flags & TTY_DRIVER_DEVPTS_MEM) {
		tty = devpts_get_tty(idx);
		if (tty && driver->subtype == PTY_TYPE_MASTER)
			tty = tty->link;
	} else {
		tty = driver->ttys[idx];
	}
	if (tty) goto fast_track;

	if (!try_module_get(driver->owner)) {
		retval = -ENODEV;
		goto end_init;
	}

	o_tty = NULL;
	tp = o_tp = NULL;
	ltp = o_ltp = NULL;

	tty = alloc_tty_struct();
	if (!tty)
		goto fail_no_mem;
	initialize_tty_struct(tty);
	tty->driver = driver;
	tty->index = idx;
	tty_line_name(driver, idx, tty->name);

	if (driver->flags & TTY_DRIVER_DEVPTS_MEM) {
		tp_loc = &tty->termios;
		ltp_loc = &tty->termios_locked;
	} else {
		tp_loc = &driver->termios[idx];
		ltp_loc = &driver->termios_locked[idx];
	}

	if (!*tp_loc) {
		tp = (struct termios *) kmalloc(sizeof(struct termios),
						GFP_KERNEL);
		if (!tp)
			goto free_mem_out;
		*tp = driver->init_termios;
	}

	if (!*ltp_loc) {
		ltp = (struct termios *) kmalloc(sizeof(struct termios),
						 GFP_KERNEL);
		if (!ltp)
			goto free_mem_out;
		memset(ltp, 0, sizeof(struct termios));
	}

	if (driver->type == TTY_DRIVER_TYPE_PTY) {
		o_tty = alloc_tty_struct();
		if (!o_tty)
			goto free_mem_out;
		initialize_tty_struct(o_tty);
		o_tty->driver = driver->other;
		o_tty->index = idx;
		tty_line_name(driver->other, idx, o_tty->name);

		if (driver->flags & TTY_DRIVER_DEVPTS_MEM) {
			o_tp_loc = &o_tty->termios;
			o_ltp_loc = &o_tty->termios_locked;
		} else {
			o_tp_loc = &driver->other->termios[idx];
			o_ltp_loc = &driver->other->termios_locked[idx];
		}

		if (!*o_tp_loc) {
			o_tp = (struct termios *)
				kmalloc(sizeof(struct termios), GFP_KERNEL);
			if (!o_tp)
				goto free_mem_out;
			*o_tp = driver->other->init_termios;
		}

		if (!*o_ltp_loc) {
			o_ltp = (struct termios *)
				kmalloc(sizeof(struct termios), GFP_KERNEL);
			if (!o_ltp)
				goto free_mem_out;
			memset(o_ltp, 0, sizeof(struct termios));
		}

		if (!(driver->other->flags & TTY_DRIVER_DEVPTS_MEM)) {
			driver->other->ttys[idx] = o_tty;
		}
		if (!*o_tp_loc)
			*o_tp_loc = o_tp;
		if (!*o_ltp_loc)
			*o_ltp_loc = o_ltp;
		o_tty->termios = *o_tp_loc;
		o_tty->termios_locked = *o_ltp_loc;
		driver->other->refcount++;
		if (driver->subtype == PTY_TYPE_MASTER)
			o_tty->count++;

		/* Establish the links in both directions */
		tty->link   = o_tty;
		o_tty->link = tty;
	}

	if (!(driver->flags & TTY_DRIVER_DEVPTS_MEM)) {
		driver->ttys[idx] = tty;
	}

	if (!*tp_loc)
		*tp_loc = tp;
	if (!*ltp_loc)
		*ltp_loc = ltp;
	tty->termios = *tp_loc;
	tty->termios_locked = *ltp_loc;
	driver->refcount++;
	tty->count++;

	if (tty->ldisc.open) {
		retval = (tty->ldisc.open)(tty);
		if (retval)
			goto release_mem_out;
	}
	if (o_tty && o_tty->ldisc.open) {
		retval = (o_tty->ldisc.open)(o_tty);
		if (retval) {
			if (tty->ldisc.close)
				(tty->ldisc.close)(tty);
			goto release_mem_out;
		}
		tty_ldisc_enable(o_tty);
	}
	tty_ldisc_enable(tty);
	goto success;

fast_track:
	if (test_bit(TTY_CLOSING, &tty->flags)) {
		retval = -EIO;
		goto end_init;
	}
	if (driver->type == TTY_DRIVER_TYPE_PTY &&
	    driver->subtype == PTY_TYPE_MASTER) {
		if (tty->count) {
			retval = -EIO;
			goto end_init;
		}
		tty->link->count++;
	}
	tty->count++;
	tty->driver = driver;

	if(!test_bit(TTY_LDISC, &tty->flags))
		printk(KERN_ERR "init_dev but no ldisc\n");
success:
	*ret_tty = tty;
end_init:
	return retval;

free_mem_out:
	if (o_tp)
		kfree(o_tp);
	if (o_tty)
		free_tty_struct(o_tty);
	if (ltp)
		kfree(ltp);
	if (tp)
		kfree(tp);
	free_tty_struct(tty);

fail_no_mem:
	module_put(driver->owner);
	retval = -ENOMEM;
	goto end_init;

release_mem_out:
	printk(KERN_INFO "init_dev: ldisc open failed, "
			 "clearing slot %d\n", idx);
	release_mem(tty, idx);
	goto end_init;
}

static void release_mem(struct tty_struct *tty, int idx)
{
    panic("in release_mem");
}

static void release_dev(struct file * filp)
{
    panic("in release_dev");
}

static int tty_open(struct inode * inode, struct file * filp)
{
    struct tty_struct *tty;
	int noctty, retval;
	struct tty_driver *driver;
	int index;
	dev_t device = inode->i_rdev;
	unsigned short saved_flags = filp->f_flags;

	nonseekable_open(inode, filp);
retry_open:
	noctty = filp->f_flags & O_NOCTTY;
	index = -1;
	retval = 0;

	down(&tty_sem);

	if (device == MKDEV(TTYAUX_MAJOR, 0)) {
		if (!current->signal->tty) {
			up(&tty_sem);
			return -ENXIO;
		}
		driver = current->signal->tty->driver;
		index = current->signal->tty->index;
		filp->f_flags |= O_NONBLOCK;
		goto got_driver;
	}
#ifdef CONFIG_VT
	if (device == MKDEV(TTY_MAJOR,0)) {
		extern int fg_console;
		extern struct tty_driver *console_driver;
		driver = console_driver;
		index = fg_console;
		noctty = 1;
		goto got_driver;
	}
#endif
	if (device == MKDEV(TTYAUX_MAJOR, 1)) {
		driver = console_device(&index);
		if (driver) {
			filp->f_flags |= O_NONBLOCK;
			noctty = 1;
			goto got_driver;
		}
		up(&tty_sem);
		return -ENODEV;
	}

	driver = get_tty_driver(device, &index);
	if (!driver) {
		up(&tty_sem);
		return -ENODEV;
	}
got_driver:
	retval = init_dev(driver, index, &tty);
	up(&tty_sem);
	if (retval)
		return retval;
	
	filp->private_data = tty;
	file_move(filp, &tty->tty_files);
	check_tty_count(tty, "tty_open");
	if (tty->driver->type == TTY_DRIVER_TYPE_PTY &&
	    tty->driver->subtype == PTY_TYPE_MASTER)
		noctty = 1;
#ifdef TTY_DEBUG_HANGUP
	printk(KERN_DEBUG "opening %s...", tty->name);
#endif
	if (!retval) {
		if (tty->driver->open)
			retval = tty->driver->open(tty, filp);
		else
			retval = -ENODEV;
	}
	filp->f_flags = saved_flags;
	if (!retval && test_bit(TTY_EXCLUSIVE, &tty->flags) && !capable(CAP_SYS_ADMIN))
		retval = -EBUSY;

	if (retval) {
#ifdef TTY_DEBUG_HANGUP
		printk(KERN_DEBUG "error %d in opening %s...", retval,
		       tty->name);
#endif
		release_dev(filp);
		if (retval != -ERESTARTSYS)
			return retval;
		if (signal_pending(current))
			return retval;
		schedule();
		if (filp->f_op == &hung_up_tty_fops)
			filp->f_op = &tty_fops;
		goto retry_open;
	}
	if (!noctty &&
		current->signal->leader &&
		!current->signal->tty &&
		tty->session == 0) {
			task_lock(current);
		current->signal->tty = tty;
		task_unlock(current);
		current->signal->tty_old_pgrp = 0;
		tty->session = current->signal->session;
		tty->pgrp = process_group(current);
	}
	return 0;
}

#ifdef CONFIG_UNIX98_PTYS
static int ptmx_open(struct inode * inode, struct file * filp)
{
	panic("in ptmx_open");
	return 0;
}
#endif

static int tty_release(struct inode * inode, struct file * filp)
{
	lock_kernel();
	release_dev(filp);
	unlock_kernel();
	return 0;
}

static unsigned int tty_poll(struct file * filp, poll_table * wait)
{
    panic("in tty_poll");
    return 0;
}

static int tty_fasync(int fd, struct file * filp, int on)
{
    panic("in tty_fasync");
    return 0;
}

static int tiocsti(struct tty_struct *tty, char __user *p)
{
    panic("in tiocsti");
    return 0;
}

static int tiocgwinsz(struct tty_struct *tty, struct winsize __user * arg)
{
	if (copy_to_user(arg, &tty->winsize, sizeof(*arg)))
		return -EFAULT;
	return 0;
}

static int tiocswinsz(struct tty_struct *tty, struct tty_struct *real_tty,
	struct winsize __user * arg)
{
    panic("in tiocswinsz");
    return 0;
}

static int tioccons(struct file *file)
{
    panic("in tioccons");
    return 0;
}

static int fionbio(struct file *file, int __user *p)
{
	int nonblock;

	if (get_user(nonblock, p))
		return -EFAULT;

	if (nonblock)
		file->f_flags |= O_NONBLOCK;
	else
		file->f_flags &= ~O_NONBLOCK;
	return 0;
}

static int tiocsctty(struct tty_struct *tty, int arg)
{
    panic("in tiocsctty");
    return 0;
}

static int tiocgpgrp(struct tty_struct *tty, struct tty_struct *real_tty, pid_t __user *p)
{
	/*
	 * (tty == real_tty) is a cheap way of
	 * testing if the tty is NOT a master pty.
	 */
	if (tty == real_tty && current->signal->tty != real_tty)
		return -ENOTTY;
	return put_user(real_tty->pgrp, p);
}

static int tiocspgrp(struct tty_struct *tty, struct tty_struct *real_tty, pid_t __user *p)
{
    panic("in tiocspgrp");
    return 0;
}

static int tiocgsid(struct tty_struct *tty, struct tty_struct *real_tty, pid_t __user *p)
{
	/*
	 * (tty == real_tty) is a cheap way of
	 * testing if the tty is NOT a master pty.
	*/
	if (tty == real_tty && current->signal->tty != real_tty)
		return -ENOTTY;
	if (real_tty->session <= 0)
		return -ENOTTY;
	return put_user(real_tty->session, p);
}

static int tiocsetd(struct tty_struct *tty, int __user *p)
{
    panic("in tiocsetd");
    return 0;
}

static int send_break(struct tty_struct *tty, int duration)
{
	tty->driver->break_ctl(tty, -1);
	if (!signal_pending(current)) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(duration);
	}
	tty->driver->break_ctl(tty, 0);
	if (signal_pending(current))
		return -EINTR;
	return 0;
}

static int
tty_tiocmget(struct tty_struct *tty, struct file *file, int __user *p)
{
	int retval = -EINVAL;

	if (tty->driver->tiocmget) {
		retval = tty->driver->tiocmget(tty, file);

		if (retval >= 0)
			retval = put_user(retval, p);
	}
	return retval;
}


static int
tty_tiocmset(struct tty_struct *tty, struct file *file, unsigned int cmd,
	     unsigned __user *p)
{
    panic("in tty_tiocmset");
    return 0;
}

int tty_ioctl(struct inode * inode, struct file * file,
	      unsigned int cmd, unsigned long arg)
{
    panic("in tty_ioctl");
    return 0;
}

static void __do_SAK(void *arg)
{
    panic("in __do_SAK");
}

void do_SAK(struct tty_struct *tty)
{
	if (!tty)
		return;
	PREPARE_WORK(&tty->SAK_work, __do_SAK, tty);
	schedule_work(&tty->SAK_work);
}

EXPORT_SYMBOL(do_SAK);

static void flush_to_ldisc(void *private_)
{
    panic("in flush_to_ldisc");
}

static int baud_table[] = {
	0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800,
	9600, 19200, 38400, 57600, 115200, 230400, 460800,
#ifdef __sparc__
	76800, 153600, 307200, 614400, 921600
#else
	500000, 576000, 921600, 1000000, 1152000, 1500000, 2000000,
	2500000, 3000000, 3500000, 4000000
#endif
};

static int n_baud_table = ARRAY_SIZE(baud_table);

int tty_termios_baud_rate(struct termios *termios)
{
	unsigned int cbaud;
	
	cbaud = termios->c_cflag & CBAUD;

	if (cbaud & CBAUDEX) {
		cbaud &= ~CBAUDEX;

		if (cbaud < 1 || cbaud + 15 > n_baud_table)
			termios->c_cflag &= ~CBAUDEX;
		else
			cbaud += 15;
	}
	return baud_table[cbaud];
}

EXPORT_SYMBOL(tty_termios_baud_rate);

int tty_get_baud_rate(struct tty_struct *tty)
{
    panic("in tty_get_baud_rate");
    return 0;
}

EXPORT_SYMBOL(tty_get_baud_rate);

void tty_flip_buffer_push(struct tty_struct *tty)
{
	if (tty->low_latency)
		flush_to_ldisc((void *) tty);
	else
		schedule_delayed_work(&tty->flip.work, 1);
}

EXPORT_SYMBOL(tty_flip_buffer_push);

static void initialize_tty_struct(struct tty_struct *tty)
{
    memset(tty, 0, sizeof(struct tty_struct));
	tty->magic = TTY_MAGIC;
	tty_ldisc_assign(tty, tty_ldisc_get(N_TTY));
	tty->pgrp = -1;
	tty->flip.char_buf_ptr = tty->flip.char_buf;
	tty->flip.flag_buf_ptr = tty->flip.flag_buf;
	INIT_WORK(&tty->flip.work, flush_to_ldisc, tty);
	init_MUTEX(&tty->flip.pty_sem);
	init_MUTEX(&tty->termios_sem);
	init_waitqueue_head(&tty->write_wait);
	init_waitqueue_head(&tty->read_wait);
	INIT_WORK(&tty->hangup_work, do_tty_hangup, tty);
	sema_init(&tty->atomic_read, 1);
	sema_init(&tty->atomic_write, 1);
	spin_lock_init(&tty->read_lock);
	INIT_LIST_HEAD(&tty->tty_files);
	INIT_WORK(&tty->SAK_work, NULL, NULL);
}

static void tty_default_put_char(struct tty_struct *tty, unsigned char ch)
{
	tty->driver->write(tty, &ch, 1);
}

static struct class_simple *tty_class;

void tty_register_device(struct tty_driver *driver, unsigned index,
			 struct device *device)
{
	char name[64];
	dev_t dev = MKDEV(driver->major, driver->minor_start + index);

	if (index >= driver->num) {
		printk(KERN_ERR "Attempt to register invalid tty line number "
		       " (%d).\n", index);
		return;
	}

	devfs_mk_cdev(dev, S_IFCHR | S_IRUSR | S_IWUSR,
			"%s%d", driver->devfs_name, index + driver->name_base);
	
	if (driver->type == TTY_DRIVER_TYPE_PTY)
		pty_line_name(driver, index, name);
	else
		tty_line_name(driver, index, name);
	class_simple_device_add(tty_class, dev, device, name);
}

void tty_unregister_device(struct tty_driver *driver, unsigned index)
{
    devfs_remove("%s%d", driver->devfs_name, index + driver->name_base);
	class_simple_device_remove(MKDEV(driver->major, driver->minor_start) + index);
}

EXPORT_SYMBOL(tty_register_device);
EXPORT_SYMBOL(tty_unregister_device);

struct tty_driver *alloc_tty_driver(int lines)
{
	struct tty_driver *driver;

	driver = kmalloc(sizeof(struct tty_driver), GFP_KERNEL);
	if (driver) {
		memset(driver, 0, sizeof(struct tty_driver));
		driver->magic = TTY_DRIVER_MAGIC;
		driver->num = lines;
		/* later we'll move allocation of tables here */
	}
	return driver;
}

void put_tty_driver(struct tty_driver *driver)
{
	kfree(driver);
}

void tty_set_operations(struct tty_driver *driver, struct tty_operations *op)
{
	driver->open = op->open;
	driver->close = op->close;
	driver->write = op->write;
	driver->put_char = op->put_char;
	driver->flush_chars = op->flush_chars;
	driver->write_room = op->write_room;
	driver->chars_in_buffer = op->chars_in_buffer;
	driver->ioctl = op->ioctl;
	driver->set_termios = op->set_termios;
	driver->throttle = op->throttle;
	driver->unthrottle = op->unthrottle;
	driver->stop = op->stop;
	driver->start = op->start;
	driver->hangup = op->hangup;
	driver->break_ctl = op->break_ctl;
	driver->flush_buffer = op->flush_buffer;
	driver->set_ldisc = op->set_ldisc;
	driver->wait_until_sent = op->wait_until_sent;
	driver->send_xchar = op->send_xchar;
	driver->read_proc = op->read_proc;
	driver->write_proc = op->write_proc;
	driver->tiocmget = op->tiocmget;
	driver->tiocmset = op->tiocmset;
}

EXPORT_SYMBOL(alloc_tty_driver);
EXPORT_SYMBOL(put_tty_driver);
EXPORT_SYMBOL(tty_set_operations);

int tty_register_driver(struct tty_driver *driver)
{
	int error;
        int i;
	dev_t dev;
	void **p = NULL;

	if (driver->flags & TTY_DRIVER_INSTALLED)
		return 0;
	
	if (!(driver->flags & TTY_DRIVER_DEVPTS_MEM)) {
		p = kmalloc(driver->num * 3 * sizeof(void *), GFP_KERNEL);
		if (!p)
			return -ENOMEM;
		memset(p, 0, driver->num * 3 * sizeof(void *));
	}

	if (!driver->major) {
		error = alloc_chrdev_region(&dev, driver->minor_start, driver->num,
						(char*)driver->name);
		if (!error) {
			driver->major = MAJOR(dev);
			driver->minor_start = MINOR(dev);
		}
	} else {
		dev = MKDEV(driver->major, driver->minor_start);
		error = register_chrdev_region(dev, driver->num,
						(char*)driver->name);
	}
	if (error < 0) {
		kfree(p);
		return error;
	}

	if (p) {
		driver->ttys = (struct tty_struct **)p;
		driver->termios = (struct termios **)(p + driver->num);
		driver->termios_locked = (struct termios **)(p + driver->num * 2);
	} else {
		driver->ttys = NULL;
		driver->termios = NULL;
		driver->termios_locked = NULL;
	}

	cdev_init(&driver->cdev, &tty_fops);
	driver->cdev.owner = driver->owner;
	error = cdev_add(&driver->cdev, dev, driver->num);
	if (error) {
		cdev_del(&driver->cdev);
		unregister_chrdev_region(dev, driver->num);
		driver->ttys = NULL;
		driver->termios = driver->termios_locked = NULL;
		kfree(p);
		return error;
	}

	if (!driver->put_char)
		driver->put_char = tty_default_put_char;

	list_add(&driver->tty_drivers, &tty_drivers);

	if (!(driver->flags & TTY_DRIVER_NO_DEVFS)) {
		for(i = 0; i < driver->num; i++)
		    tty_register_device(driver, i, NULL);
	}
	proc_tty_register_driver(driver);
	return 0;
}

EXPORT_SYMBOL(tty_register_driver);

int tty_unregister_driver(struct tty_driver *driver)
{
    panic("in tty_unregister_driver");
    return 0;
}

EXPORT_SYMBOL(tty_unregister_driver);

/*
 * Initialize the console device. This is called *early*, so
 * we can't necessarily depend on lots of kernel help here.
 * Just do some early initializations, and do the complex setup
 * later.
 */
void __init console_init(void) {
    initcall_t *call;

    /* Setup the default TTY line discipline. */
	(void) tty_register_ldisc(N_TTY, &tty_ldisc_N_TTY);

    /*
	 * set up the console device so that later boot sequences can 
	 * inform about problems etc..
	 */
#ifdef CONFIG_EARLY_PRINTK
	// disable_early_printk();
#endif
#ifdef CONFIG_SERIAL_68360
#error "CONFIG_SERIAL_68360"
#endif
    call = __con_initcall_start;
    while (call < __con_initcall_end) {
        (*call)();
        call++;
    }
}

#ifdef CONFIG_VT
extern int vty_init(void);
#endif

static int __init tty_class_init(void)
{
	tty_class = class_simple_create(THIS_MODULE, "tty");
	if (IS_ERR(tty_class))
		return PTR_ERR(tty_class);
	return 0;
}

postcore_initcall(tty_class_init);

static struct cdev tty_cdev, console_cdev;
#ifdef CONFIG_UNIX98_PTYS
static struct cdev ptmx_cdev;
#endif
#ifdef CONFIG_VT
static struct cdev vc0_cdev;
#endif

static int __init tty_init(void)
{
    cdev_init(&tty_cdev, &tty_fops);
	if (cdev_add(&tty_cdev, MKDEV(TTYAUX_MAJOR, 0), 1) ||
		register_chrdev_region(MKDEV(TTYAUX_MAJOR, 0), 1, "/dev/tty") < 0)
		panic("Couldn't register /dev/tty driver\n");
	devfs_mk_cdev(MKDEV(TTYAUX_MAJOR, 0), S_IFCHR|S_IRUGO|S_IWUGO, "tty");
	class_simple_device_add(tty_class, MKDEV(TTYAUX_MAJOR, 0), NULL, "tty");

	cdev_init(&console_cdev, &console_fops);
	if (cdev_add(&console_cdev, MKDEV(TTYAUX_MAJOR, 1), 1) ||
	    register_chrdev_region(MKDEV(TTYAUX_MAJOR, 1), 1, "/dev/console") < 0)
		panic("Couldn't register /dev/console driver\n");
	devfs_mk_cdev(MKDEV(TTYAUX_MAJOR, 1), S_IFCHR|S_IRUSR|S_IWUSR, "console");
	class_simple_device_add(tty_class, MKDEV(TTYAUX_MAJOR, 1), NULL, "console");

#ifdef CONFIG_UNIX98_PTYS
	cdev_init(&ptmx_cdev, &ptmx_fops);
	if (cdev_add(&ptmx_cdev, MKDEV(TTYAUX_MAJOR, 2), 1) ||
	    register_chrdev_region(MKDEV(TTYAUX_MAJOR, 2), 1, "/dev/ptmx") < 0)
		panic("Couldn't register /dev/ptmx driver\n");
	devfs_mk_cdev(MKDEV(TTYAUX_MAJOR, 2), S_IFCHR|S_IRUGO|S_IWUGO, "ptmx");
	class_simple_device_add(tty_class, MKDEV(TTYAUX_MAJOR, 2), NULL, "ptmx");
#endif

#ifdef CONFIG_VT
	cdev_init(&vc0_cdev, &console_fops);
	if (cdev_add(&vc0_cdev, MKDEV(TTY_MAJOR, 0), 1) ||
	    register_chrdev_region(MKDEV(TTY_MAJOR, 0), 1, "/dev/vc/0") < 0)
		panic("Couldn't register /dev/tty0 driver\n");
	devfs_mk_cdev(MKDEV(TTY_MAJOR, 0), S_IFCHR|S_IRUSR|S_IWUSR, "vc/0");
	class_simple_device_add(tty_class, MKDEV(TTY_MAJOR, 0), NULL, "tty0");

	vty_init();
#endif

    return 0;
}

module_init(tty_init);