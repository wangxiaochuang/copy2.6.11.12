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

static void kbd_disconnect(struct input_handle *handle);
extern void ctrl_alt_del(void);

#define KBD_DEFMODE ((1 << VC_REPEAT) | (1 << VC_META))

#if defined(CONFIG_PARISC) && (defined(CONFIG_KEYBOARD_HIL) || defined(CONFIG_KEYBOARD_HIL_OLD))
#define KBD_DEFLEDS (1 << VC_NUMLOCK)
#else
#define KBD_DEFLEDS 0
#endif

#define KBD_DEFLOCK 0

void compute_shiftstate(void);

#define K_HANDLERS\
	k_self,		k_fn,		k_spec,		k_pad,\
	k_dead,		k_cons,		k_cur,		k_shift,\
	k_meta,		k_ascii,	k_lock,		k_lowercase,\
	k_slock,	k_dead2,	k_ignore,	k_ignore

typedef void (k_handler_fn)(struct vc_data *vc, unsigned char value, 
			    char up_flag, struct pt_regs *regs);
static k_handler_fn K_HANDLERS;
static k_handler_fn *k_handler[16] = { K_HANDLERS };

#define FN_HANDLERS\
	fn_null, 	fn_enter,	fn_show_ptregs,	fn_show_mem,\
	fn_show_state,	fn_send_intr, 	fn_lastcons, 	fn_caps_toggle,\
	fn_num,		fn_hold, 	fn_scroll_forw,	fn_scroll_back,\
	fn_boot_it, 	fn_caps_on, 	fn_compose,	fn_SAK,\
	fn_dec_console, fn_inc_console, fn_spawn_con, 	fn_bare_num

typedef void (fn_handler_fn)(struct vc_data *vc, struct pt_regs *regs);
static fn_handler_fn FN_HANDLERS;
static fn_handler_fn *fn_handler[] = { FN_HANDLERS };

const int max_vals[] = {
	255, ARRAY_SIZE(func_table) - 1, ARRAY_SIZE(fn_handler) - 1, NR_PAD - 1,
	NR_DEAD - 1, 255, 3, NR_SHIFT - 1, 255, NR_ASCII - 1, NR_LOCK - 1,
	255, NR_LOCK - 1, 255
};

const int NR_TYPES = ARRAY_SIZE(max_vals);

struct kbd_struct kbd_table[MAX_NR_CONSOLES];
static struct kbd_struct *kbd = kbd_table;
static struct kbd_struct kbd0;

int spawnpid, spawnsig;

int shift_state = 0;

/*
 * Internal Data.
 */

static struct input_handler kbd_handler;
static unsigned long key_down[NBITS(KEY_MAX)];		/* keyboard key bitmap */
static unsigned char shift_down[NR_SHIFT];		/* shift state counters.. */
static int dead_key_next;
static int npadch = -1;					/* -1 or number assembled on pad */
static unsigned char diacr;
static char rep;					/* flag telling character repeat */

static unsigned char ledstate = 0xff;			/* undefined */
static unsigned char ledioctl;

static struct ledptr {
	unsigned int *addr;
	unsigned int mask;
	unsigned char valid:1;
} ledptrs[3];

#ifdef CONFIG_MAGIC_SYSRQ
unsigned char kbd_sysrq_xlate[KEY_MAX] =
        "\000\0331234567890-=\177\t"                    /* 0x00 - 0x0f */
        "qwertyuiop[]\r\000as"                          /* 0x10 - 0x1f */
        "dfghjkl;'`\000\\zxcv"                          /* 0x20 - 0x2f */
        "bnm,./\000*\000 \000\201\202\203\204\205"      /* 0x30 - 0x3f */
        "\206\207\210\211\212\000\000789-456+1"         /* 0x40 - 0x4f */
        "230\177\000\000\213\214\000\000\000\000\000\000\000\000\000\000" /* 0x50 - 0x5f */
        "\r\000/";                                      /* 0x60 - 0x6f */
static int sysrq_down;
#endif
static int sysrq_alt;

int getkeycode(unsigned int scancode)
{
	panic("in getkeycode");
	return 0;
}

int setkeycode(unsigned int scancode, unsigned int keycode)
{
	panic("in setkeycode");
	return 0;
}

static void kd_nosound(unsigned long ignored)
{
	panic("in kd_nosound");
}

static struct timer_list kd_mksound_timer =
		TIMER_INITIALIZER(kd_nosound, 0, 0);

void kd_mksound(unsigned int hz, unsigned int ticks)
{
	panic("in kd_mksound");
}

int kbd_rate(struct kbd_repeat *rep)
{
	panic("in kbd_rate");
	return 0;
}

static void put_queue(struct vc_data *vc, int ch)
{
	panic("in put_queue");
}

static void puts_queue(struct vc_data *vc, char *cp)
{
	panic("in puts_queue");
}

static void applkey(struct vc_data *vc, int key, char mode)
{
	static char buf[] = { 0x1b, 'O', 0x00, 0x00 };

	buf[1] = (mode ? 'O' : '[');
	buf[2] = key;
	puts_queue(vc, buf);
}

static void to_utf8(struct vc_data *vc, ushort c)
{
	if (c < 0x80)
		/*  0******* */
		put_queue(vc, c);
    	else if (c < 0x800) {
		/* 110***** 10****** */
		put_queue(vc, 0xc0 | (c >> 6)); 
		put_queue(vc, 0x80 | (c & 0x3f));
    	} else {
		/* 1110**** 10****** 10****** */
		put_queue(vc, 0xe0 | (c >> 12));
		put_queue(vc, 0x80 | ((c >> 6) & 0x3f));
		put_queue(vc, 0x80 | (c & 0x3f));
    }
}

/* 
 * Called after returning from RAW mode or when changing consoles - recompute
 * shift_down[] and shift_state from key_down[] maybe called when keymap is
 * undefined, so that shiftkey release is seen
 */
void compute_shiftstate(void)
{
	panic("in compute_shiftstate");
}

static unsigned char handle_diacr(struct vc_data *vc, unsigned char ch)
{
	panic("in handle_diacr");
	return ch;
}

static void fn_enter(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_enter");
}

static void fn_caps_toggle(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_caps_toggle");
}

static void fn_caps_on(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_caps_on");
}

static void fn_show_ptregs(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_show_ptregs");
}

static void fn_hold(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_hold");
}

static void fn_num(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_num");
}

static void fn_bare_num(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_bare_num");
}

static void fn_lastcons(struct vc_data *vc, struct pt_regs *regs)
{
	/* switch to the last used console, ChN */
	set_console(last_console);
}

static void fn_dec_console(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_dec_console");
}

static void fn_inc_console(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_inc_console");
}

static void fn_send_intr(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_send_intr");
}

static void fn_scroll_forw(struct vc_data *vc, struct pt_regs *regs)
{
	scrollfront(0);
}

static void fn_scroll_back(struct vc_data *vc, struct pt_regs *regs)
{
	scrollback(0);
}

static void fn_show_mem(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_show_mem");
}

static void fn_show_state(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_show_state");
}

static void fn_boot_it(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_boot_it");
}

static void fn_compose(struct vc_data *vc, struct pt_regs *regs)
{
	dead_key_next = 1;
}

static void fn_spawn_con(struct vc_data *vc, struct pt_regs *regs)
{
	if (spawnpid)
		if(kill_proc(spawnpid, spawnsig, 1))
			spawnpid = 0;
}

static void fn_SAK(struct vc_data *vc, struct pt_regs *regs)
{ 
	panic("in fn_SAK");
}

static void fn_null(struct vc_data *vc, struct pt_regs *regs)
{
	panic("in fn_null");
}

static void k_ignore(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
}

static void k_spec(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	panic("in k_spec");
}

static void k_lowercase(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	printk(KERN_ERR "keyboard.c: k_lowercase was called - impossible\n");
}

static void k_self(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	panic("in k_self");
}

static void k_dead2(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	panic("in k_dead2");
}

static void k_dead(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	panic("in k_dead");
}

static void k_cons(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	if (up_flag)
		return;
	set_console(value);
}

static void k_fn(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	unsigned v;

	if (up_flag)
		return;
	v = value;
	if (v < ARRAY_SIZE(func_table)) {
		if (func_table[value])
			puts_queue(vc, func_table[value]);
	} else
		printk(KERN_ERR "k_fn called with value=%d\n", value);
}

static void k_cur(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	static const char *cur_chars = "BDCA";

	if (up_flag)
		return;
	applkey(vc, cur_chars[value], vc_kbd_mode(kbd, VC_CKMODE));
}

static void k_pad(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	panic("in k_pad");
}

static void k_shift(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	panic("in k_shift");
}

static void k_meta(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	panic("in k_meta");
}

static void k_ascii(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	int base;

	if (up_flag)
		return;

	if (value < 10) {
		/* decimal input of code, while Alt depressed */
		base = 10;
	} else {
		/* hexadecimal input of code, while AltGr depressed */
		value -= 10;
		base = 16;
	}

	if (npadch == -1)
		npadch = value;
	else
		npadch = npadch * base + value;
}

static void k_lock(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	panic("in k_lock");
}

static void k_slock(struct vc_data *vc, unsigned char value, char up_flag, struct pt_regs *regs)
{
	panic("in k_slock");
}

unsigned char getledstate(void)
{
	return ledstate;
}

void setledstate(struct kbd_struct *kbd, unsigned int led)
{
	panic("in setledstate");
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

static void kbd_refresh_leds(struct input_handle *handle)
{
	panic("in kbd_refresh_leds");
}

#if defined(CONFIG_X86) || defined(CONFIG_IA64) || defined(CONFIG_ALPHA) ||\
    defined(CONFIG_MIPS) || defined(CONFIG_PPC) || defined(CONFIG_SPARC32) ||\
    defined(CONFIG_SPARC64) || defined(CONFIG_PARISC) || defined(CONFIG_SUPERH) ||\
    (defined(CONFIG_ARM) && defined(CONFIG_KEYBOARD_ATKBD) && !defined(CONFIG_RPC))

#define HW_RAW(dev) (test_bit(EV_MSC, dev->evbit) && test_bit(MSC_RAW, dev->mscbit) &&\
			((dev)->id.bustype == BUS_I8042) && ((dev)->id.vendor == 0x0001) && ((dev)->id.product == 0x0001))

static unsigned short x86_keycodes[256] =
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
	 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
	 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
	 80, 81, 82, 83, 84,118, 86, 87, 88,115,120,119,121,112,123, 92,
	284,285,309,298,312, 91,327,328,329,331,333,335,336,337,338,339,
	367,288,302,304,350, 89,334,326,267,126,268,269,125,347,348,349,
	360,261,262,263,268,376,100,101,321,316,373,286,289,102,351,355,
	103,104,105,275,287,279,306,106,274,107,294,364,358,363,362,361,
	291,108,381,281,290,272,292,305,280, 99,112,257,258,359,113,114,
	264,117,271,374,379,265,266, 93, 94, 95, 85,259,375,260, 90,116,
	377,109,111,277,278,282,283,295,296,297,299,300,301,293,303,307,
	308,310,313,314,315,317,318,319,320,357,322,323,324,325,276,330,
	332,340,365,342,343,344,345,346,356,270,341,368,369,370,371,372 };

#ifdef CONFIG_MAC_EMUMOUSEBTN
extern int mac_hid_mouse_emulate_buttons(int, int, int);
#endif /* CONFIG_MAC_EMUMOUSEBTN */

#if defined(CONFIG_SPARC32) || defined(CONFIG_SPARC64)
static int sparc_l1_a_state = 0;
extern void sun_do_break(void);
#endif

static int emulate_raw(struct vc_data *vc, unsigned int keycode, 
		       unsigned char up_flag)
{
	panic("in emulate_raw");
	return 0;
}

#else
#endif

static void kbd_rawcode(unsigned char data)
{
	struct vc_data *vc = vc_cons[fg_console].d;
	kbd = kbd_table + fg_console;
	if (kbd->kbdmode == VC_RAW)
		put_queue(vc, data);
}

void kbd_keycode(unsigned int keycode, int down, int hw_raw, struct pt_regs *regs)
{
	panic("in kbd_keycode");
}

static void kbd_event(struct input_handle *handle, unsigned int event_type, 
		      unsigned int event_code, int value)
{
	panic("in kbd_event");
}

static char kbd_name[] = "kbd";

static struct input_handle *kbd_connect(struct input_handler *handler, 
					struct input_dev *dev,
					struct input_device_id *id)
{
	panic("in kbd_connect");
	return NULL;
}

static void kbd_disconnect(struct input_handle *handle)
{
	panic("in kbd_disconnect");
}

static struct input_device_id kbd_ids[] = {
	{
                .flags = INPUT_DEVICE_ID_MATCH_EVBIT,
                .evbit = { BIT(EV_KEY) },
        },
	
	{
                .flags = INPUT_DEVICE_ID_MATCH_EVBIT,
                .evbit = { BIT(EV_SND) },
        },	

	{ },    /* Terminating entry */
};

MODULE_DEVICE_TABLE(input, kbd_ids);

static struct input_handler kbd_handler = {
	.event		= kbd_event,
	.connect	= kbd_connect,
	.disconnect	= kbd_disconnect,
	.name		= "kbd",
	.id_table	= kbd_ids,
};

int __init kbd_init(void)
{
	int i;

        kbd0.ledflagstate = kbd0.default_ledflagstate = KBD_DEFLEDS;
        kbd0.ledmode = LED_SHOW_FLAGS;
        kbd0.lockstate = KBD_DEFLOCK;
        kbd0.slockstate = 0;
        kbd0.modeflags = KBD_DEFMODE;
        kbd0.kbdmode = VC_XLATE;

        for (i = 0 ; i < MAX_NR_CONSOLES ; i++)
                kbd_table[i] = kbd0;

	input_register_handler(&kbd_handler);

	tasklet_enable(&keyboard_tasklet);
	tasklet_schedule(&keyboard_tasklet);

	return 0;
}