#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/timex.h>
#include <linux/errno.h>
#include <linux/cpufreq.h>
#include <linux/string.h>
#include <linux/jiffies.h>

#include <asm/timer.h>
#include <asm/io.h>
/* processor.h for distable_tsc flag */
#include <asm/processor.h>

#include "io_ports.h"
#include "mach_timer.h"

#include <asm/hpet.h>

int tsc_disable __initdata = 0;

static unsigned long get_offset_tsc(void)
{
    return 0;
}

static unsigned long long monotonic_clock_tsc(void)
{
    return 0;
}

static void delay_tsc(unsigned long loops)
{
}

static void mark_offset_tsc(void)
{
}

static int __init init_tsc(char* override)
{
    mypanic("init tsc");
	return 0;
}
/************************************************************/

/* tsc timer_opts struct */
static struct timer_opts timer_tsc = {
	.name = "tsc",
	.mark_offset = mark_offset_tsc, 
	.get_offset = get_offset_tsc,
	.monotonic_clock = monotonic_clock_tsc,
	.delay = delay_tsc,
};

struct init_timer_opts __initdata timer_tsc_init = {
	.init = init_tsc,
	.opts = &timer_tsc,
};