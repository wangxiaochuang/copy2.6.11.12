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