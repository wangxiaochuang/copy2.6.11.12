#include <linux/config.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/timer.h>
#include <linux/kernel.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/major.h>
#include <linux/fs.h>
#include <linux/console.h>

#include <asm/io.h>
#include <asm/uaccess.h>

#include <linux/kbd_kern.h>
#include <linux/vt_kern.h>
#include <linux/kbd_diacr.h>
#include <linux/selection.h>

char vt_dont_switch;
extern struct tty_driver *console_driver;

#define VT_IS_IN_USE(i)	(console_driver->ttys[i] && console_driver->ttys[i]->count)
#define VT_BUSY(i)	(VT_IS_IN_USE(i) || i == fg_console || vc_cons[i].d == sel_cons)

/*
 * Console (vt and kd) routines, as defined by USL SVR4 manual, and by
 * experimentation and study of X386 SYSV handling.
 *
 * One point of difference: SYSV vt's are /dev/vtX, which X >= 0, and
 * /dev/console is a separate ttyp. Under Linux, /dev/tty0 is /dev/console,
 * and the vc start at /dev/ttyX, X >= 1. We maintain that here, so we will
 * always treat our set of vt as numbered 1..MAX_NR_CONSOLES (corresponding to
 * ttys 0..MAX_NR_CONSOLES-1). Explicitly naming VT 0 is illegal, but using
 * /dev/tty0 (fg_console) as a target is legal, since an implicit aliasing
 * to the current console is done by the main ioctl code.
 */

struct vt_struct *vt_cons[MAX_NR_CONSOLES];

/*
 * Sometimes we want to wait until a particular VT has been activated. We
 * do it in a very simple manner. Everybody waits on a single queue and
 * get woken up at once. Those that are satisfied go on with their business,
 * while those not ready go back to sleep. Seems overkill to add a wait
 * to each vt just for this - usually this does nothing!
 */
static DECLARE_WAIT_QUEUE_HEAD(vt_activate_queue);

#define vt_wake_waitactive() wake_up(&vt_activate_queue)

void reset_vc(unsigned int new_console)
{
	vt_cons[new_console]->vc_mode = KD_TEXT;
	kbd_table[new_console].kbdmode = VC_XLATE;
	vt_cons[new_console]->vt_mode.mode = VT_AUTO;
	vt_cons[new_console]->vt_mode.waitv = 0;
	vt_cons[new_console]->vt_mode.relsig = 0;
	vt_cons[new_console]->vt_mode.acqsig = 0;
	vt_cons[new_console]->vt_mode.frsig = 0;
	vt_cons[new_console]->vt_pid = -1;
	vt_cons[new_console]->vt_newvt = -1;
	if (!in_interrupt())    /* Via keyboard.c:SAK() - akpm */
		reset_palette(new_console) ;
}

/*
 * Performs the back end of a vt switch
 */
void complete_change_console(unsigned int new_console)
{
	unsigned char old_vc_mode;

	last_console = fg_console;

	/*
	 * If we're switching, we could be going from KD_GRAPHICS to
	 * KD_TEXT mode or vice versa, which means we need to blank or
	 * unblank the screen later.
	 */
	old_vc_mode = vt_cons[fg_console]->vc_mode;
	switch_screen(new_console);

	/*
	 * This can't appear below a successful kill_proc().  If it did,
	 * then the *blank_screen operation could occur while X, having
	 * received acqsig, is waking up on another processor.  This
	 * condition can lead to overlapping accesses to the VGA range
	 * and the framebuffer (causing system lockups).
	 *
	 * To account for this we duplicate this code below only if the
	 * controlling process is gone and we've called reset_vc.
	 */
	if (old_vc_mode != vt_cons[new_console]->vc_mode)
	{
		if (vt_cons[new_console]->vc_mode == KD_TEXT)
			do_unblank_screen(1);
		else
			do_blank_screen(1);
	}

	/*
	 * If this new console is under process control, send it a signal
	 * telling it that it has acquired. Also check if it has died and
	 * clean up (similar to logic employed in change_console())
	 */
	if (vt_cons[new_console]->vt_mode.mode == VT_PROCESS)
	{
		/*
		 * Send the signal as privileged - kill_proc() will
		 * tell us if the process has gone or something else
		 * is awry
		 */
		if (kill_proc(vt_cons[new_console]->vt_pid,
			      vt_cons[new_console]->vt_mode.acqsig,
			      1) != 0)
		{
		/*
		 * The controlling process has died, so we revert back to
		 * normal operation. In this case, we'll also change back
		 * to KD_TEXT mode. I'm not sure if this is strictly correct
		 * but it saves the agony when the X server dies and the screen
		 * remains blanked due to KD_GRAPHICS! It would be nice to do
		 * this outside of VT_PROCESS but there is no single process
		 * to account for and tracking tty count may be undesirable.
		 */
		        reset_vc(new_console);

			if (old_vc_mode != vt_cons[new_console]->vc_mode)
			{
				if (vt_cons[new_console]->vc_mode == KD_TEXT)
					do_unblank_screen(1);
				else
					do_blank_screen(1);
			}
		}
	}

	/*
	 * Wake anyone waiting for their VT to activate
	 */
	vt_wake_waitactive();
	return;
}

/*
 * Performs the front-end of a vt switch
 */
void change_console(unsigned int new_console)
{
        if ((new_console == fg_console) || (vt_dont_switch))
                return;
        if (!vc_cons_allocated(new_console))
		return;

	/*
	 * If this vt is in process mode, then we need to handshake with
	 * that process before switching. Essentially, we store where that
	 * vt wants to switch to and wait for it to tell us when it's done
	 * (via VT_RELDISP ioctl).
	 *
	 * We also check to see if the controlling process still exists.
	 * If it doesn't, we reset this vt to auto mode and continue.
	 * This is a cheap way to track process control. The worst thing
	 * that can happen is: we send a signal to a process, it dies, and
	 * the switch gets "lost" waiting for a response; hopefully, the
	 * user will try again, we'll detect the process is gone (unless
	 * the user waits just the right amount of time :-) and revert the
	 * vt to auto control.
	 */
	if (vt_cons[fg_console]->vt_mode.mode == VT_PROCESS)
	{
		/*
		 * Send the signal as privileged - kill_proc() will
		 * tell us if the process has gone or something else
		 * is awry
		 */
		if (kill_proc(vt_cons[fg_console]->vt_pid,
			      vt_cons[fg_console]->vt_mode.relsig,
			      1) == 0)
		{
			/*
			 * It worked. Mark the vt to switch to and
			 * return. The process needs to send us a
			 * VT_RELDISP ioctl to complete the switch.
			 */
			vt_cons[fg_console]->vt_newvt = new_console;
			return;
		}

		/*
		 * The controlling process has died, so we revert back to
		 * normal operation. In this case, we'll also change back
		 * to KD_TEXT mode. I'm not sure if this is strictly correct
		 * but it saves the agony when the X server dies and the screen
		 * remains blanked due to KD_GRAPHICS! It would be nice to do
		 * this outside of VT_PROCESS but there is no single process
		 * to account for and tracking tty count may be undesirable.
		 */
		reset_vc(fg_console);

		/*
		 * Fall through to normal (VT_AUTO) handling of the switch...
		 */
	}

	/*
	 * Ignore all switches in KD_GRAPHICS+VT_AUTO mode
	 */
	if (vt_cons[fg_console]->vc_mode == KD_GRAPHICS)
		return;

	complete_change_console(new_console);
}