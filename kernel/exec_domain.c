#include <linux/config.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/personality.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/sysctl.h>
#include <linux/types.h>

static void default_handler(int, struct pt_regs *);

static u_long ident_map[32] = {
	0,	1,	2,	3,	4,	5,	6,	7,
	8,	9,	10,	11,	12,	13,	14,	15,
	16,	17,	18,	19,	20,	21,	22,	23,
	24,	25,	26,	27,	28,	29,	30,	31
};

struct exec_domain default_exec_domain = {
	.name		= "Linux",		/* name */
	.handler	= default_handler,	/* lcall7 causes a seg fault. */
	.pers_low	= 0, 			/* PER_LINUX personality. */
	.pers_high	= 0,			/* PER_LINUX personality. */
	.signal_map	= ident_map,		/* Identity map signals. */
	.signal_invmap	= ident_map,		/*  - both ways. */
};

static void
default_handler(int segment, struct pt_regs *regp) {

}