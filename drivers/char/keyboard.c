#include <linux/config.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <linux/kbd_kern.h>
#include <linux/kbd_diacr.h>
#include <linux/vt_kern.h>
#include <linux/sysrq.h>
#include <linux/input.h>

struct kbd_struct kbd_table[MAX_NR_CONSOLES];

/*
 * Internal Data.
 */

static struct input_handler kbd_handler;

static unsigned char ledstate = 0xff;			/* undefined */
static unsigned char ledioctl;

static struct ledptr {
	unsigned int *addr;
	unsigned int mask;
	unsigned char valid:1;
} ledptrs[3];

/* 
 * Called after returning from RAW mode or when changing consoles - recompute
 * shift_down[] and shift_state from key_down[] maybe called when keymap is
 * undefined, so that shiftkey release is seen
 */
void compute_shiftstate(void)
{
}

static inline unsigned char getleds(void)
{
	struct kbd_struct *kbd = kbd_table + fg_console;
	unsigned char leds;
	int i;

	if (kbd->ledmode == LED_SHOW_IOCTL)
		return ledioctl;

	leds = kbd->ledflagstate;

	if (kbd->ledmode == LED_SHOW_MEM) {
		for (i = 0; i < 3; i++)
			if (ledptrs[i].valid) {
				if (*ledptrs[i].addr & ledptrs[i].mask)
					leds |= (1 << i);
				else
					leds &= ~(1 << i);
			}
	}
	return leds;
}

/*
 * This routine is the bottom half of the keyboard interrupt
 * routine, and runs with all interrupts enabled. It does
 * console changing, led setting and copy_to_cooked, which can
 * take a reasonably long time.
 *
 * Aside from timing (which isn't really that important for
 * keyboard interrupts as they happen often), using the software
 * interrupt routines for this thing allows us to easily mask
 * this when we don't want any of the above to happen.
 * This allows for easy and efficient race-condition prevention
 * for kbd_refresh_leds => input_event(dev, EV_LED, ...) => ...
 */

static void kbd_bh(unsigned long dummy)
{
	struct list_head * node;
	unsigned char leds = getleds();

	if (leds != ledstate) {
		list_for_each(node,&kbd_handler.h_list) {
			struct input_handle * handle = to_handle_h(node);
			input_event(handle->dev, EV_LED, LED_SCROLLL, !!(leds & 0x01));
			input_event(handle->dev, EV_LED, LED_NUML,    !!(leds & 0x02));
			input_event(handle->dev, EV_LED, LED_CAPSL,   !!(leds & 0x04));
			input_sync(handle->dev);
		}
	}

	ledstate = leds;
}

DECLARE_TASKLET_DISABLED(keyboard_tasklet, kbd_bh, 0);