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

static unsigned long hpet_usec_quotient;
static unsigned long tsc_hpet_quotient;

static unsigned long cyc2ns_scale;
#define CYC2NS_SCALE_FACTOR 10 /* 2^10, carefully chosen */

static inline void set_cyc2ns_scale(unsigned long cpu_mhz)
{
	cyc2ns_scale = (1000 << CYC2NS_SCALE_FACTOR)/cpu_mhz;
}

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
	unsigned long result, remain;

	/* check clock override */
	if (override[0] && strncmp(override,"hpet",4))
		return -ENODEV;

	if (!is_hpet_enabled())
		return -ENODEV;

	printk("Using HPET for gettimeofday\n");
	if (cpu_has_tsc) {
		unsigned long tsc_quotient = calibrate_tsc_hpet(&tsc_hpet_quotient);
		if (tsc_quotient) {
			/* report CPU clock rate in Hz.
			 * The formula is (10^6 * 2^32) / (2^32 * 1 / (clocks/us)) =
			 * clock/second. Our precision is about 100 ppm.
			 */
			{	unsigned long eax=0, edx=1000;
				ASM_DIV64_REG(cpu_khz, edx, tsc_quotient,
						eax, edx);
				printk("Detected %lu.%03lu MHz processor.\n",
					cpu_khz / 1000, cpu_khz % 1000);
			}
			set_cyc2ns_scale(cpu_khz/1000);
		}
	}

	/*
	 * Math to calculate hpet to usec multiplier
	 * Look for the comments at get_offset_hpet()
	 */
	ASM_DIV64_REG(result, remain, hpet_tick, 0, KERNEL_TICK_USEC);
	if (remain > (hpet_tick >> 1))
		result++; /* rounding the result */
	hpet_usec_quotient = result;

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