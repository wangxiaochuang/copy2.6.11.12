#include <linux/utsname.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/string.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/genhd.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>

#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/irq.h>
#include <asm/io.h>

struct timer_rand_state {
	cycles_t last_time;
	long last_delta,last_delta2;
	unsigned dont_count_entropy:1;
};

static struct timer_rand_state input_timer_state;
static struct timer_rand_state extract_timer_state;
static struct timer_rand_state *irq_timer_state[NR_IRQS];

void add_interrupt_randomness(int irq) {
    panic("in add_interrupt_randomness");
}

void rand_initialize_irq(int irq) {
    panic("in rand_initialize_irq");
}

void rand_initialize_disk(struct gendisk *disk)
{
    struct timer_rand_state *state;

	/*
	 * If kmalloc returns null, we just won't use that entropy
	 * source.
	 */
	state = kmalloc(sizeof(struct timer_rand_state), GFP_KERNEL);
	if (state) {
		memset(state, 0, sizeof(struct timer_rand_state));
		disk->random = state;
	}
}