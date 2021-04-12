#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/tty.h>
#include <linux/console.h>
#include <linux/string.h>
#include <linux/kd.h>
#include <linux/slab.h>
#include <linux/vt_kern.h>
#include <linux/selection.h>
#include <linux/spinlock.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <video/vga.h>
#include <asm/io.h>

static DEFINE_SPINLOCK(vga_lock);
static int cursor_size_lastfrom;
static int cursor_size_lastto;
static struct vgastate state;

#define BLANK 0x0020

#define CAN_LOAD_EGA_FONTS	/* undefine if the user must not do this */
#define CAN_LOAD_PALETTE	/* undefine if the user must not do this */

/* You really do _NOT_ want to define this, unless you have buggy
 * Trident VGA which will resize cursor when moving it between column
 * 15 & 16. If you define this and your VGA is OK, inverse bug will
 * appear.
 */
#undef TRIDENT_GLITCH

/*
 *  Interface used by the world
 */

static const char *vgacon_startup(void);
static void vgacon_init(struct vc_data *c, int init);
static void vgacon_deinit(struct vc_data *c);
static void vgacon_cursor(struct vc_data *c, int mode);
static int vgacon_switch(struct vc_data *c);
static int vgacon_blank(struct vc_data *c, int blank, int mode_switch);
static int vgacon_set_palette(struct vc_data *vc, unsigned char *table);
static int vgacon_scrolldelta(struct vc_data *c, int lines);
static int vgacon_set_origin(struct vc_data *c);
static void vgacon_save_screen(struct vc_data *c);
static int vgacon_scroll(struct vc_data *c, int t, int b, int dir,
			 int lines);
static u8 vgacon_build_attr(struct vc_data *c, u8 color, u8 intensity,
			    u8 blink, u8 underline, u8 reverse);
static void vgacon_invert_region(struct vc_data *c, u16 * p, int count);
static unsigned long vgacon_uni_pagedir[2];


/* Description of the hardware situation */
static unsigned long	vga_vram_base;		/* Base of video memory */
static unsigned long	vga_vram_end;		/* End of video memory */
static u16		vga_video_port_reg;	/* Video register select port */
static u16		vga_video_port_val;	/* Video register value port */
static unsigned int	vga_video_num_columns;	/* Number of text columns */
static unsigned int	vga_video_num_lines;	/* Number of text lines */
static int		vga_can_do_color = 0;	/* Do we support colors? */
static unsigned int	vga_default_font_height;/* Height of default screen font */
static unsigned char	vga_video_type;		/* Card type */
static unsigned char	vga_hardscroll_enabled;
static unsigned char	vga_hardscroll_user_enable = 1;
static unsigned char	vga_font_is_default = 1;
static int		vga_vesa_blanked;
static int 		vga_palette_blanked;
static int 		vga_is_gfx;
static int 		vga_512_chars;
static int 		vga_video_font_height;
static int 		vga_scan_lines;
static unsigned int 	vga_rolled_over = 0;

static int __init no_scroll(char *str)
{
	/*
	 * Disabling scrollback is required for the Braillex ib80-piezo
	 * Braille reader made by F.H. Papenmeier (Germany).
	 * Use the "no-scroll" bootflag.
	 */
	vga_hardscroll_user_enable = vga_hardscroll_enabled = 0;
	return 1;
}

__setup("no-scroll", no_scroll);

static const char __init *vgacon_startup(void)
{
    return NULL;
}

static void vgacon_init(struct vc_data *c, int init) {

}

static void vgacon_deinit(struct vc_data *c) {

}

static u8 vgacon_build_attr(struct vc_data *c, u8 color, u8 intensity,
			    u8 blink, u8 underline, u8 reverse) {
    u8 attr = color;
    return attr;
}

static void vgacon_invert_region(struct vc_data *c, u16 * p, int count) {

}

static void vgacon_set_cursor_size(int xpos, int from, int to) {

}

static void vgacon_cursor(struct vc_data *c, int mode) {

}

static int vgacon_switch(struct vc_data *c) {
    return 0;
}

static int vgacon_set_palette(struct vc_data *vc, unsigned char *table) {
	return 0;
}

/* structure holding original VGA register settings */
static struct {
	unsigned char SeqCtrlIndex;	/* Sequencer Index reg.   */
	unsigned char CrtCtrlIndex;	/* CRT-Contr. Index reg.  */
	unsigned char CrtMiscIO;	/* Miscellaneous register */
	unsigned char HorizontalTotal;	/* CRT-Controller:00h */
	unsigned char HorizDisplayEnd;	/* CRT-Controller:01h */
	unsigned char StartHorizRetrace;	/* CRT-Controller:04h */
	unsigned char EndHorizRetrace;	/* CRT-Controller:05h */
	unsigned char Overflow;	/* CRT-Controller:07h */
	unsigned char StartVertRetrace;	/* CRT-Controller:10h */
	unsigned char EndVertRetrace;	/* CRT-Controller:11h */
	unsigned char ModeControl;	/* CRT-Controller:17h */
	unsigned char ClockingMode;	/* Seq-Controller:01h */
} vga_state;

static void vga_vesa_blank(struct vgastate *state, int mode) {

}

static void vga_vesa_unblank(struct vgastate *state) {

}

static int vgacon_blank(struct vc_data *c, int blank, int mode_switch) {
    return 0;
}

#ifdef CAN_LOAD_EGA_FONTS

static int vgacon_do_font_op(struct vgastate *state,char *arg,int set,int ch512) {
    return 0;
}

/*
 * Adjust the screen to fit a font of a certain height
 */
static int vgacon_adjust_height(struct vc_data *vc, unsigned fontheight) {
    return 0;
}

static int vgacon_font_set(struct vc_data *c, struct console_font *font, unsigned flags) {
    return 0;
}

static int vgacon_font_get(struct vc_data *c, struct console_font *font) {
    return 0;
}

#else

#define vgacon_font_set NULL
#define vgacon_font_get NULL

#endif

static int vgacon_scrolldelta(struct vc_data *c, int lines) {
    return 0;
}

static int vgacon_set_origin(struct vc_data *c) {
    return 0;
}

static void vgacon_save_screen(struct vc_data *c) {

}

static int vgacon_scroll(struct vc_data *c, int t, int b, int dir,
			 int lines) {
	return 0;
}

/*
 *  The console `switch' structure for the VGA based console
 */

static int vgacon_dummy(struct vc_data *c) {
	return 0;
}

#define DUMMY (void *) vgacon_dummy

const struct consw vga_con = {
	.owner = THIS_MODULE,
	.con_startup = vgacon_startup,
	.con_init = vgacon_init,
	.con_deinit = vgacon_deinit,
	.con_clear = DUMMY,
	.con_putc = DUMMY,
	.con_putcs = DUMMY,
	.con_cursor = vgacon_cursor,
	.con_scroll = vgacon_scroll,
	.con_bmove = DUMMY,
	.con_switch = vgacon_switch,
	.con_blank = vgacon_blank,
	.con_font_set = vgacon_font_set,
	.con_font_get = vgacon_font_get,
	.con_set_palette = vgacon_set_palette,
	.con_scrolldelta = vgacon_scrolldelta,
	.con_set_origin = vgacon_set_origin,
	.con_save_screen = vgacon_save_screen,
	.con_build_attr = vgacon_build_attr,
	.con_invert_region = vgacon_invert_region,
};

MODULE_LICENSE("GPL");