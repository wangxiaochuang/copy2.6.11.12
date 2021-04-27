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

#ifdef CONFIG_HPET_TIMER
static unsigned long hpet_usec_quotient;
static unsigned long hpet_last;
static struct timer_opts timer_tsc;
#endif

int tsc_disable __initdata = 0;

extern spinlock_t i8253_lock;

static int use_tsc;
/* Number of usecs that the last interrupt was delayed */
static int delay_at_last_interrupt;

static unsigned long last_tsc_low; /* lsb 32 bits of Time Stamp Counter */
static unsigned long last_tsc_high; /* msb 32 bits of Time Stamp Counter */
static unsigned long long monotonic_base;
static seqlock_t monotonic_lock = SEQLOCK_UNLOCKED;

static unsigned long cyc2ns_scale; 
#define CYC2NS_SCALE_FACTOR 10 /* 2^10, carefully chosen */

static inline void set_cyc2ns_scale(unsigned long cpu_mhz)
{
	cyc2ns_scale = (1000 << CYC2NS_SCALE_FACTOR)/cpu_mhz;
}

static inline unsigned long long cycles_2_ns(unsigned long long cyc)
{
	return (cyc * cyc2ns_scale) >> CYC2NS_SCALE_FACTOR;
}

static int count2; /* counter for mark_offset_tsc() */

/* Cached *multiplier* to convert TSC counts to microseconds.
 * (see the equation below).
 * Equal to 2^32 * (1 / (clocks per usec) ).
 * Initialized in time_init.
 */
static unsigned long fast_gettimeoffset_quotient;

static unsigned long get_offset_tsc(void)
{
    register unsigned long eax, edx;

	/* Read the Time Stamp Counter */

	rdtsc(eax,edx);

	/* .. relative to previous jiffy (32 bits is enough) */
	eax -= last_tsc_low;	/* tsc_low delta */

	/*
         * Time offset = (tsc_low delta) * fast_gettimeoffset_quotient
         *             = (tsc_low delta) * (usecs_per_clock)
         *             = (tsc_low delta) * (usecs_per_jiffy / clocks_per_jiffy)
	 *
	 * Using a mull instead of a divl saves up to 31 clock cycles
	 * in the critical path.
         */

	__asm__("mull %2"
		:"=a" (eax), "=d" (edx)
		:"rm" (fast_gettimeoffset_quotient),
		 "0" (eax));

	/* our adjusted time offset in microseconds */
	return delay_at_last_interrupt + edx;
}

static unsigned long long monotonic_clock_tsc(void)
{
    unsigned long long last_offset, this_offset, base;
	unsigned seq;
	
	/* atomically read monotonic base & last_offset */
	do {
		seq = read_seqbegin(&monotonic_lock);
		last_offset = ((unsigned long long)last_tsc_high<<32)|last_tsc_low;
		base = monotonic_base;
	} while (read_seqretry(&monotonic_lock, seq));

	/* Read the Time Stamp Counter */
	rdtscll(this_offset);

	/* return the value in ns */
	return base + cycles_2_ns(this_offset - last_offset);
}

static void delay_tsc(unsigned long loops)
{
	unsigned long bclock, now;
	
	rdtscl(bclock);
	do
	{
		rep_nop();
		rdtscl(now);
	} while ((now-bclock) < loops);
}

#ifdef CONFIG_HPET_TIMER
static void mark_offset_tsc_hpet(void)
{
	unsigned long long this_offset, last_offset;
 	unsigned long offset, temp, hpet_current;

	write_seqlock(&monotonic_lock);
	last_offset = ((unsigned long long)last_tsc_high<<32)|last_tsc_low;
	/*
	 * It is important that these two operations happen almost at
	 * the same time. We do the RDTSC stuff first, since it's
	 * faster. To avoid any inconsistencies, we need interrupts
	 * disabled locally.
	 */
	/*
	 * Interrupts are just disabled locally since the timer irq
	 * has the SA_INTERRUPT flag set. -arca
	 */
	/* read Pentium cycle counter */

	hpet_current = hpet_readl(HPET_COUNTER);
	rdtsc(last_tsc_low, last_tsc_high);

	/* lost tick compensation */
	offset = hpet_readl(HPET_T0_CMP) - hpet_tick;
	if (unlikely(((offset - hpet_last) > hpet_tick) && (hpet_last != 0))) {
		int lost_ticks = (offset - hpet_last) / hpet_tick;
		jiffies_64 += lost_ticks;
	}
	hpet_last = hpet_current;

	/* update the monotonic base value */
	this_offset = ((unsigned long long)last_tsc_high<<32)|last_tsc_low;
	monotonic_base += cycles_2_ns(this_offset - last_offset);
	write_sequnlock(&monotonic_lock);

	/* calculate delay_at_last_interrupt */
	/*
	 * Time offset = (hpet delta) * ( usecs per HPET clock )
	 *             = (hpet delta) * ( usecs per tick / HPET clocks per tick)
	 *             = (hpet delta) * ( hpet_usec_quotient ) / (2^32)
	 * Where,
	 * hpet_usec_quotient = (2^32 * usecs per tick)/HPET clocks per tick
	 */
	delay_at_last_interrupt = hpet_current - offset;
	ASM_MUL64_REG(temp, delay_at_last_interrupt,
			hpet_usec_quotient, delay_at_last_interrupt);
}
#endif


#ifdef CONFIG_CPU_FREQ
#include <linux/workqueue.h>

static unsigned int cpufreq_delayed_issched = 0;
static unsigned int cpufreq_init = 0;
static struct work_struct cpufreq_delayed_get_work;

static inline void cpufreq_delayed_get(void) 
{
	if (cpufreq_init && !cpufreq_delayed_issched) {
		cpufreq_delayed_issched = 1;
		printk(KERN_DEBUG "Losing some ticks... checking if CPU frequency changed.\n");
		schedule_work(&cpufreq_delayed_get_work);
	}
}

static int __init cpufreq_tsc(void) {
	return 0;
}

core_initcall(cpufreq_tsc);
#else
#error "CONFIG_CPU_FREQ"
#endif

static void mark_offset_tsc(void)
{
	unsigned long lost,delay;
	unsigned long delta = last_tsc_low;
	int count;
	int countmp;
	static int count1 = 0;
	unsigned long long this_offset, last_offset;
	static int lost_count = 0;

	write_seqlock(&monotonic_lock);
	last_offset = ((unsigned long long)last_tsc_high<<32)|last_tsc_low;

	rdtsc(last_tsc_low, last_tsc_high);

	spin_lock(&i8253_lock);
	outb_p(0x00, PIT_MODE);     /* latch the count ASAP */

	count = inb_p(PIT_CH0);    /* read the latched count */
	count |= inb(PIT_CH0) << 8;

	/*
	 * VIA686a test code... reset the latch if count > max + 1
	 * from timer_pit.c - cjb
	 */
	if (count > LATCH) {
		outb_p(0x34, PIT_MODE);
		outb_p(LATCH & 0xff, PIT_CH0);
		outb(LATCH >> 8, PIT_CH0);
		count = LATCH - 1;
	}

	spin_unlock(&i8253_lock);

	if (pit_latch_buggy) {
		/* get center value of last 3 time lutch */
		if ((count2 >= count && count >= count1)
		    || (count1 >= count && count >= count2)) {
			count2 = count1; count1 = count;
		} else if ((count1 >= count2 && count2 >= count)
			   || (count >= count2 && count2 >= count1)) {
			countmp = count;count = count2;
			count2 = count1;count1 = countmp;
		} else {
			count2 = count1; count1 = count; count = count1;
		}
	}

	/* lost tick compensation */
	delta = last_tsc_low - delta;
	{
		register unsigned long eax, edx;
		eax = delta;
		__asm__("mull %2"
		:"=a" (eax), "=d" (edx)
		:"rm" (fast_gettimeoffset_quotient),
		 "0" (eax));
		delta = edx;
	}

	delta += delay_at_last_interrupt;
	lost = delta/(1000000/HZ);
	delay = delta%(1000000/HZ);
	if (lost >= 2) {
		jiffies_64 += lost-1;

		/* sanity check to ensure we're not always losing ticks */
		if (lost_count++ > 100) {
			printk(KERN_WARNING "Losing too many ticks!\n");
			printk(KERN_WARNING "TSC cannot be used as a timesource.  \n");
			printk(KERN_WARNING "Possible reasons for this are:\n");
			printk(KERN_WARNING "  You're running with Speedstep,\n");
			printk(KERN_WARNING "  You don't have DMA enabled for your hard disk (see hdparm),\n");
			printk(KERN_WARNING "  Incorrect TSC synchronization on an SMP system (see dmesg).\n");
			printk(KERN_WARNING "Falling back to a sane timesource now.\n");

			clock_fallback();
		}
		/* ... but give the TSC a fair chance */
		if (lost_count > 25)
			cpufreq_delayed_get();
	} else
		lost_count = 0;
	/* update the monotonic base value */
	this_offset = ((unsigned long long)last_tsc_high<<32)|last_tsc_low;
	monotonic_base += cycles_2_ns(this_offset - last_offset);
	write_sequnlock(&monotonic_lock);

	/* calculate delay_at_last_interrupt */
	count = ((LATCH-1) - count) * TICK_SIZE;
	delay_at_last_interrupt = (count + LATCH/2) / LATCH;

	/* catch corner case where tick rollover occured
	 * between tsc and pit reads (as noted when
	 * usec delta is > 90% # of usecs/tick)
	 */
	if (lost && abs(delay - delay_at_last_interrupt) > (900000/HZ))
		jiffies_64++;
}

static int __init init_tsc(char* override)
{
	/* check clock override */
	if (override[0] && strncmp(override,"tsc",3)) {
#ifdef CONFIG_HPET_TIMER
		if (is_hpet_enabled()) {
			printk(KERN_ERR "Warning: clock= override failed. Defaulting to tsc\n");
		} else
#endif
		{
			return -ENODEV;
		}
	}

	count2 = LATCH; /* initialize counter for mark_offset_tsc() */

	if (cpu_has_tsc) {
		unsigned long tsc_quotient;
#ifdef CONFIG_HPET_TIMER
		if (is_hpet_enabled()){
			unsigned long result, remain;
			printk("Using TSC for gettimeofday\n");
			tsc_quotient = calibrate_tsc_hpet(NULL);
			timer_tsc.mark_offset = &mark_offset_tsc_hpet;
			/*
			 * Math to calculate hpet to usec multiplier
			 * Look for the comments at get_offset_tsc_hpet()
			 */
			ASM_DIV64_REG(result, remain, hpet_tick,
					0, KERNEL_TICK_USEC);
			if (remain > (hpet_tick >> 1))
				result++; /* rounding the result */

			hpet_usec_quotient = result;
		} else
#endif
		{
			tsc_quotient = calibrate_tsc();
		}

		if (tsc_quotient) {
			fast_gettimeoffset_quotient = tsc_quotient;
			use_tsc = 1;
			/*
			 *	We could be more selective here I suspect
			 *	and just enable this for the next intel chips ?
			 */
			/* report CPU clock rate in Hz.
			 * The formula is (10^6 * 2^32) / (2^32 * 1 / (clocks/us)) =
			 * clock/second. Our precision is about 100 ppm.
			 */
			{	unsigned long eax=0, edx=1000;
				__asm__("divl %2"
		       		:"=a" (cpu_khz), "=d" (edx)
        	       		:"r" (tsc_quotient),
	                	"0" (eax), "1" (edx));
				printk("Detected %lu.%03lu MHz processor.\n", cpu_khz / 1000, cpu_khz % 1000);
			}
			set_cyc2ns_scale(cpu_khz/1000);
			return 0;
		}
	}
	return -ENODEV;
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