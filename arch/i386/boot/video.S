#include <linux/config.h> /* for CONFIG_VIDEO_* */

/* Disable video select */
#undef CONFIG_VIDEO_SELECT

/* Enable autodetection of SVGA adapters and modes. */
#undef CONFIG_VIDEO_SVGA

/* Enable autodetection of VESA modes */
#define CONFIG_VIDEO_VESA

/* Enable compacting of mode table */
#define CONFIG_VIDEO_COMPACT

/* Retain screen contents when switching modes */
#define CONFIG_VIDEO_RETAIN

/* Enable local mode list */
#undef CONFIG_VIDEO_LOCAL

/* Force 400 scan lines for standard modes (hack to fix bad BIOS behaviour */
#undef CONFIG_VIDEO_400_HACK

/* Hack that lets you force specific BIOS mode ID and specific dimensions */
#undef CONFIG_VIDEO_GFX_HACK
#define VIDEO_GFX_BIOS_AX 0x4f02	/* 800x600 on ThinkPad */
#define VIDEO_GFX_BIOS_BX 0x0102
#define VIDEO_GFX_DUMMY_RESOLUTION 0x6425	/* 100x37 */

/* This code uses an extended set of video mode numbers. These include:
 * Aliases for standard modes
 *	NORMAL_VGA (-1)
 *	EXTENDED_VGA (-2)
 *	ASK_VGA (-3)
 * Video modes numbered by menu position -- NOT RECOMMENDED because of lack
 * of compatibility when extending the table. These are between 0x00 and 0xff.
 */
#define VIDEO_FIRST_MENU 0x0000

/* Standard BIOS video modes (BIOS number + 0x0100) */
#define VIDEO_FIRST_BIOS 0x0100

/* VESA BIOS video modes (VESA number + 0x0200) */
#define VIDEO_FIRST_VESA 0x0200

/* Video7 special modes (BIOS number + 0x0900) */
#define VIDEO_FIRST_V7 0x0900

/* Special video modes */
#define VIDEO_FIRST_SPECIAL 0x0f00
#define VIDEO_80x25 0x0f00
#define VIDEO_8POINT 0x0f01
#define VIDEO_80x43 0x0f02
#define VIDEO_80x28 0x0f03
#define VIDEO_CURRENT_MODE 0x0f04
#define VIDEO_80x30 0x0f05
#define VIDEO_80x34 0x0f06
#define VIDEO_80x60 0x0f07
#define VIDEO_GFX_HACK 0x0f08
#define VIDEO_LAST_SPECIAL 0x0f09

/* Video modes given by resolution */
#define VIDEO_FIRST_RESOLUTION 0x1000

/* The "recalculate timings" flag */
#define VIDEO_RECALC 0x8000

/* Positions of various video parameters passed to the kernel */
/* (see also include/linux/tty.h) */
#define PARAM_CURSOR_POS	0x00
#define PARAM_VIDEO_PAGE	0x04
#define PARAM_VIDEO_MODE	0x06
#define PARAM_VIDEO_COLS	0x07
#define PARAM_VIDEO_EGA_BX	0x0a
#define PARAM_VIDEO_LINES	0x0e
#define PARAM_HAVE_VGA		0x0f
#define PARAM_FONT_POINTS	0x10

#define PARAM_LFB_WIDTH		0x12
#define PARAM_LFB_HEIGHT	0x14
#define PARAM_LFB_DEPTH		0x16
#define PARAM_LFB_BASE		0x18
#define PARAM_LFB_SIZE		0x1c
#define PARAM_LFB_LINELENGTH	0x24
#define PARAM_LFB_COLORS	0x26
#define PARAM_VESAPM_SEG	0x2e
#define PARAM_VESAPM_OFF	0x30
#define PARAM_LFB_PAGES		0x32
#define PARAM_VESA_ATTRIB	0x34

/* Define DO_STORE according to CONFIG_VIDEO_RETAIN */
#ifdef CONFIG_VIDEO_RETAIN
#define DO_STORE call store_screen
#else
#define DO_STORE
#endif /* CONFIG_VIDEO_RETAIN */

video:
	pushw	%ds
	pushw	%ds		# FS contains original DS
	popw	%fs
	pushw	%cs		# DS is equal to CS
	popw	%ds
	pushw	%cs		# ES is equal to CS
	popw	%es
	xorw	%ax, %ax
	movw	%ax, %gs	# GS is zero
	cld
	call	basic_detect

#ifdef CONFIG_VIDEO_SELECT
	hlt
#endif
	call	mode_params
	popw	%ds
	ret

# Detect if we have CGA, MDA, EGA or VGA and pass it to the kernel.
basic_detect:
	movb	$0, %fs:(PARAM_HAVE_VGA)
	movb	$0x12, %ah	# Check EGA/VGA
	movb	$0x10, %bl
	int	$0x10
	movw	%bx, %fs:(PARAM_VIDEO_EGA_BX)	# Identifies EGA to the kernel
	cmpb	$0x10, %bl			# No, it's a CGA/MDA/HGA card.
	je	basret

	incb	adapter
	movw	$0x1a00, %ax			# Check EGA or VGA?
	int	$0x10
	cmpb	$0x1a, %al			# 1a means VGA...
	jne	basret				# anything else is EGA.
	
	incb	%fs:(PARAM_HAVE_VGA)		# We've detected a VGA
	incb	adapter
basret:
	ret
mode_params:
#ifdef CONFIG_VIDEO_SELECT
	hlt
#endif	
	movb	$0x03, %ah			# Read cursor position
	xorb	%bh, %bh
	int	$0x10
	movw	%dx, %fs:(PARAM_CURSOR_POS)
	movb	$0x0f, %ah			# Read page/mode/width
	int	$0x10
	movw	%bx, %fs:(PARAM_VIDEO_PAGE)
	movw	%ax, %fs:(PARAM_VIDEO_MODE)	# Video mode and screen width
	cmpb	$0x7, %al			# MDA/HGA => segment differs
	jnz	mopar0
	hlt

mopar0:
	movw	%gs:(0x485), %ax		# Font size
	movw	%ax, %fs:(PARAM_FONT_POINTS)	# (valid only on EGA/VGA)
	movw	force_size, %ax			# Forced size?
	orw		%ax, %ax
	jz	mopar1
	hlt

mopar1:
	movb	$25, %al
	cmpb	$0, adapter			# If we are on CGA/MDA/HGA, the
	jz	mopar2				# screen must have 25 lines.

	movb	%gs:(0x484), %al		# On EGA/VGA, use the EGA+ BIOS
	incb	%al				# location of max lines.
mopar2: 
	movb	%al, %fs:(PARAM_VIDEO_LINES)
	ret

# Other variables:
adapter:	.byte	0	# Video adapter: 0=CGA/MDA/HGA,1=EGA,2=VGA
video_segment:	.word	0xb800	# Video memory segment
force_size:	.word	0	# Use this size instead of the one in BIOS vars