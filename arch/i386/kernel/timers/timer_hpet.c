#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/timex.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/jiffies.h>

#include <asm/timer.h>
#include <asm/io.h>
#include <asm/processor.h>

#include "io_ports.h"
#include "mach_timer.h"
#include <asm/hpet.h>

static unsigned long long monotonic_clock_hpet(void)
{
    return 0;
}

static unsigned long get_offset_hpet(void)
{
    return 0;
}

static void mark_offset_hpet(void)
{
}

void delay_hpet(unsigned long loops) {

}

static int __init init_hpet(char* override)
{
    mypanic("init hpet");
	return 0;
}

/************************************************************/

/* tsc timer_opts struct */
static struct timer_opts timer_hpet = {
	.name = 		"hpet",
	.mark_offset =		mark_offset_hpet,
	.get_offset =		get_offset_hpet,
	.monotonic_clock =	monotonic_clock_hpet,
	.delay = 		delay_hpet,
};

struct init_timer_opts __initdata timer_hpet_init = {
	.init =	init_hpet,
	.opts = &timer_hpet,
};