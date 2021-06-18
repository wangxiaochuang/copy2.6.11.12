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

/* This list gets poked at by procfs and various bits of boot up code. This
   could do with some rationalisation such as pulling the tty proc function
   into this file */
   
LIST_HEAD(tty_drivers);			/* linked list of tty drivers */


/* Semaphore to protect creating and releasing a tty. This is shared with
   vt.c for deeply disgusting hack reasons */
DECLARE_MUTEX(tty_sem);

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

static struct tty_driver *get_tty_driver(dev_t device, int *index)
{
    panic("in get_tty_driver");
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
    panic("in init_dev");
    return 0;
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
    panic("in tty_open");
    return 0;
}

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
    panic("in initialize_tty_struct");
}

static void tty_default_put_char(struct tty_struct *tty, unsigned char ch)
{
	tty->driver->write(tty, &ch, 1);
}

static struct class_simple *tty_class;

void tty_register_device(struct tty_driver *driver, unsigned index,
			 struct device *device)
{
    panic("in tty_register_device");
}

void tty_unregister_device(struct tty_driver *driver, unsigned index)
{
    panic("in tty_unregister_device");
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
    panic("in tty_register_driver");
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



static int __init tty_class_init(void)
{
	tty_class = class_simple_create(THIS_MODULE, "tty");
	if (IS_ERR(tty_class))
		return PTR_ERR(tty_class);
	return 0;
}

postcore_initcall(tty_class_init);






static struct cdev tty_cdev, console_cdev;

static int __init tty_init(void)
{
    cdev_init(&tty_cdev, &tty_fops);
    return 0;
}

module_init(tty_init);