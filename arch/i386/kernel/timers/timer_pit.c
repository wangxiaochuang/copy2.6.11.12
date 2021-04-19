#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/irq.h>
#include <linux/sysdev.h>
#include <linux/timex.h>
#include <asm/delay.h>
#include <asm/mpspec.h>
#include <asm/timer.h>
#include <asm/smp.h>
#include <asm/io.h>
#include <asm/arch_hooks.h>

extern spinlock_t i8259A_lock;
extern spinlock_t i8253_lock;
#include "do_timer.h"
#include "io_ports.h"

static int __init init_pit(char* override)
{
	return 0;
}

static void mark_offset_pit(void)
{
	/* nothing needed */
}

static unsigned long long monotonic_clock_pit(void)
{
	return 0;
}

static void delay_pit(unsigned long loops)
{
	int d0;
	__asm__ __volatile__(
		"\tjmp 1f\n"
		".align 16\n"
		"1:\tjmp 2f\n"
		".align 16\n"
		"2:\tdecl %0\n\tjns 2b"
		:"=&a" (d0)
		:"0" (loops));
}

static unsigned long get_offset_pit(void)
{
	return 0;
}

/* tsc timer_opts struct */
struct timer_opts timer_pit = {
	.name = "pit",
	.mark_offset = mark_offset_pit, 
	.get_offset = get_offset_pit,
	.monotonic_clock = monotonic_clock_pit,
	.delay = delay_pit,
};

struct init_timer_opts __initdata timer_pit_init = {
	.init = init_pit, 
	.opts = &timer_pit,
};

void setup_pit_timer(void)
{
	extern spinlock_t i8253_lock;
	unsigned long flags;

	spin_lock_irqsave(&i8253_lock, flags);
	outb_p(0x34,PIT_MODE);		/* binary, mode 2, LSB/MSB, ch 0 */
	udelay(10);
	outb_p(LATCH & 0xff , PIT_CH0);	/* LSB */
	udelay(10);
	outb(LATCH >> 8 , PIT_CH0);	/* MSB */
	spin_unlock_irqrestore(&i8253_lock, flags);
}