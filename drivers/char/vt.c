#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/kd.h>
#include <linux/slab.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/devfs_fs_kernel.h>
#include <linux/vt_kern.h>
#include <linux/selection.h>
#include <linux/tiocl.h>
#include <linux/kbd_kern.h>
#include <linux/consolemap.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/config.h>
#include <linux/workqueue.h>
#include <linux/bootmem.h>
#include <linux/pm.h>
#include <linux/font.h>
#include <linux/bitops.h>

#include <asm/io.h>
#include <asm/system.h>
#include <asm/uaccess.h>

#include "console_macros.h"

const struct consw *conswitchp;

/* A bitmap for codes <32. A bit of 1 indicates that the code
 * corresponding to that bit number invokes some special action
 * (such as cursor movement) and should not be displayed as a
 * glyph unless the disp_ctrl mode is explicitly enabled.
 */
#define CTRL_ACTION 0x0d00ff81
#define CTRL_ALWAYS 0x0800f501	/* Cannot be overridden by disp_ctrl */

/*
 * Here is the default bell parameters: 750HZ, 1/8th of a second
 */
#define DEFAULT_BELL_PITCH	750
#define DEFAULT_BELL_DURATION	(HZ/8)

extern void vcs_make_devfs(struct tty_struct *tty);
extern void vcs_remove_devfs(struct tty_struct *tty);

extern void console_map_init(void);
#ifdef CONFIG_PROM_CONSOLE
extern void prom_con_init(void);
#endif
#ifdef CONFIG_MDA_CONSOLE
extern int mda_console_init(void);
#endif

struct vc vc_cons [MAX_NR_CONSOLES];

#ifndef VT_SINGLE_DRIVER
static const struct consw *con_driver_map[MAX_NR_CONSOLES];
#endif

static int con_open(struct tty_struct *, struct file *);
static void vc_init(unsigned int console, unsigned int rows,
		    unsigned int cols, int do_clear);
static void gotoxy(struct vc_data *vc, int new_x, int new_y);
static void save_cur(int currcons);
static void reset_terminal(int currcons, int do_clear);
static void con_flush_chars(struct tty_struct *tty);
static void set_vesa_blanking(char __user *p);
static void set_cursor(struct vc_data *vc);
static void hide_cursor(struct vc_data *vc);
static void console_callback(void *ignored);
static void blank_screen_t(unsigned long dummy);

static int printable;		/* Is console ready for printing? */

static int blankinterval = 10*60*HZ;

/*
 * fg_console is the current virtual console,
 * last_console is the last used one,
 * want_console is the console we want to switch to,
 * kmsg_redirect is the console for kernel messages,
 */
int fg_console;
int last_console;
int want_console = -1;
int kmsg_redirect;

static struct timer_list console_timer;
static int blank_state;
static int blank_timer_expired;
enum {
	blank_off = 0,
	blank_normal_wait,
	blank_vesa_wait,
};

static void visual_init(int currcons, int init)
{
}

/*
 * Change # of rows and columns (0 means unchanged/the size of fg_console)
 * [this is to be used together with some user program
 * like resize that changes the hardware videomode]
 */
#define VC_RESIZE_MAXCOL (32767)
#define VC_RESIZE_MAXROW (32767)
int vc_resize(int currcons, unsigned int cols, unsigned int lines)
{
	return 0;
}

/*
 *	VT102 emulator
 */

#define set_kbd(x) set_vc_kbd_mode(kbd_table+currcons,x)
#define clr_kbd(x) clr_vc_kbd_mode(kbd_table+currcons,x)
#define is_kbd(x) vc_kbd_mode(kbd_table+currcons,x)

#define decarm		VC_REPEAT
#define decckm		VC_CKMODE
#define kbdapplic	VC_APPLIC
#define lnm		VC_CRLF

/*
 * this is what the terminal answers to a ESC-Z or csi0c query.
 */
#define VT100ID "\033[?1;2c"
#define VT102ID "\033[?6c"

unsigned char color_table[] = { 0, 4, 2, 6, 1, 5, 3, 7,
				       8,12,10,14, 9,13,11,15 };

/* the default colour table, for VGA+ colour systems */
int default_red[] = {0x00,0xaa,0x00,0xaa,0x00,0xaa,0x00,0xaa,
    0x55,0xff,0x55,0xff,0x55,0xff,0x55,0xff};
int default_grn[] = {0x00,0x00,0xaa,0x55,0x00,0x00,0xaa,0xaa,
    0x55,0x55,0xff,0xff,0x55,0x55,0xff,0xff};
int default_blu[] = {0x00,0x00,0x00,0x00,0xaa,0xaa,0xaa,0xaa,
    0x55,0x55,0x55,0x55,0xff,0xff,0xff,0xff};

static void vc_init(unsigned int currcons, unsigned int rows,
			unsigned int cols, int do_clear)
{
	int j, k ;
}

/*
 * This routine initializes console interrupts, and does nothing
 * else. If you want the screen to clear, call tty_write with
 * the appropriate escape-sequence.
 */

static int __init con_init(void) {
	const char *display_desc = NULL;
	unsigned int currcons = 0;

	acquire_console_sem();
	if (conswitchp)
		display_desc = conswitchp->con_startup();
	if (!display_desc) {
		fg_console = 0;
		release_console_sem();
		return 0;
	}

	init_timer(&console_timer);
	console_timer.function = blank_screen_t;
	if (blankinterval) {
		blank_state = blank_normal_wait;
		mod_timer(&console_timer, jiffies + blankinterval);
	}

	/*
	 * kmalloc is not running yet - we use the bootmem allocator.
	 */
	for (currcons = 0; currcons < MIN_NR_CONSOLES; currcons++) {
		vc_cons[currcons].d = (struct vc_data *)
				alloc_bootmem(sizeof(struct vc_data));
		vt_cons[currcons] = (struct vt_struct *)
				alloc_bootmem(sizeof(struct vt_struct));
		vc_cons[currcons].d->vc_vt = vt_cons[currcons];
		visual_init(currcons, 1);
		screenbuf = (unsigned short *) alloc_bootmem(screenbuf_size);
		kmalloced = 0;
		vc_init(currcons, vc_cons[currcons].d->vc_rows, vc_cons[currcons].d->vc_cols,
			currcons || !sw->con_save_screen);
	}

	return 0;
}

console_initcall(con_init);

/*
 * We defer the timer blanking to work queue so it can take the console semaphore
 * (console operations can still happen at irq time, but only from printk which
 * has the console semaphore. Not perfect yet, but better than no locking
 */
static void blank_screen_t(unsigned long dummy)
{
}