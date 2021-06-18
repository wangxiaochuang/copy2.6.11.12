#include <linux/types.h>
#include <linux/major.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/timer.h>
#include <linux/ctype.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/bitops.h>

#include <asm/uaccess.h>
#include <asm/system.h>

/* number of characters left in xmit buffer before select has we have room */
#define WAKEUP_CHARS 256

struct tty_ldisc tty_ldisc_N_TTY = {
	TTY_LDISC_MAGIC,	/* magic */
	"n_tty",		/* name */
	0,			/* num */
	0,			/* flags */
//	n_tty_open,		/* open */
	NULL,
//	n_tty_close,		/* close */
	NULL,
//	n_tty_flush_buffer,	/* flush_buffer */
	NULL,
//	n_tty_chars_in_buffer,	/* chars_in_buffer */
	NULL,
//	read_chan,		/* read */
	NULL,
//	write_chan,		/* write */
	NULL,
//	n_tty_ioctl,		/* ioctl */
	NULL,
//	n_tty_set_termios,	/* set_termios */
	NULL,
//	normal_poll,		/* poll */
	NULL,
	NULL,			/* hangup */
//	n_tty_receive_buf,	/* receive_buf */
	NULL,
//	n_tty_receive_room,	/* receive_room */
	NULL,
//	n_tty_write_wakeup	/* write_wakeup */
	NULL
};

int is_ignored(int sig)
{
	return (sigismember(&current->blocked, sig) ||
	        current->sighand->action[sig-1].sa.sa_handler == SIG_IGN);
}