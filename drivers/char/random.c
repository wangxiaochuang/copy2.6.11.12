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

#define DEFAULT_POOL_SIZE 512
#define SECONDARY_POOL_SIZE 128
#define BATCH_ENTROPY_SIZE 256
#define USE_SHA

static int random_read_wakeup_thresh = 64;

static int random_write_wakeup_thresh = 128;

static int trickle_thresh = DEFAULT_POOL_SIZE * 7;

static DEFINE_PER_CPU(int, trickle_count) = 0;


static struct poolinfo {
	int poolwords;
	int tap1, tap2, tap3, tap4, tap5;
} poolinfo_table[] = {
	/* x^2048 + x^1638 + x^1231 + x^819 + x^411 + x + 1  -- 115 */
	{ 2048,	1638,	1231,	819,	411,	1 },

	/* x^1024 + x^817 + x^615 + x^412 + x^204 + x + 1 -- 290 */
	{ 1024,	817,	615,	412,	204,	1 },
#if 0				/* Alternate polynomial */
	/* x^1024 + x^819 + x^616 + x^410 + x^207 + x^2 + 1 -- 115 */
	{ 1024,	819,	616,	410,	207,	2 },
#endif

	/* x^512 + x^411 + x^308 + x^208 + x^104 + x + 1 -- 225 */
	{ 512,	411,	308,	208,	104,	1 },
#if 0				/* Alternates */
	/* x^512 + x^409 + x^307 + x^206 + x^102 + x^2 + 1 -- 95 */
	{ 512,	409,	307,	206,	102,	2 },
	/* x^512 + x^409 + x^309 + x^205 + x^103 + x^2 + 1 -- 95 */
	{ 512,	409,	309,	205,	103,	2 },
#endif

	/* x^256 + x^205 + x^155 + x^101 + x^52 + x + 1 -- 125 */
	{ 256,	205,	155,	101,	52,	1 },

	/* x^128 + x^103 + x^76 + x^51 +x^25 + x + 1 -- 105 */
	{ 128,	103,	76,	51,	25,	1 },
#if 0	/* Alternate polynomial */
	/* x^128 + x^103 + x^78 + x^51 + x^27 + x^2 + 1 -- 70 */
	{ 128,	103,	78,	51,	27,	2 },
#endif

	/* x^64 + x^52 + x^39 + x^26 + x^14 + x + 1 -- 15 */
	{ 64,	52,	39,	26,	14,	1 },

	/* x^32 + x^26 + x^20 + x^14 + x^7 + x + 1 -- 15 */
	{ 32,	26,	20,	14,	7,	1 },

	{ 0,	0,	0,	0,	0,	0 },
};

#define POOLBITS	poolwords*32
#define POOLBYTES	poolwords*4


/*
 * Static global variables
 */
static struct entropy_store *random_state; /* The default global store */
static struct entropy_store *sec_random_state; /* secondary store */
static struct entropy_store *urandom_state; /* For urandom */
static DECLARE_WAIT_QUEUE_HEAD(random_read_wait);
static DECLARE_WAIT_QUEUE_HEAD(random_write_wait);


#if (!defined (__i386__))
static inline __u32 rotate_left(int i, __u32 word)
{
	return (word << i) | (word >> (32 - i));
}
#else
static inline __u32 rotate_left(int i, __u32 word)
{
	__asm__("roll %%cl,%0"
		:"=r" (word)
		:"0" (word),"c" (i));
	return word;
}
#endif

#if 0
#else
static inline __u32 int_ln_12bits(__u32 word)
{
	/* Smear msbit right to make an n-bit mask */
	word |= word >> 8;
	word |= word >> 4;
	word |= word >> 2;
	word |= word >> 1;
	/* Remove one bit to make this a logarithm */
	word >>= 1;
	/* Count the bits set in the word */
	word -= (word >> 1) & 0x555;
	word = (word & 0x333) + ((word >> 2) & 0x333);
	word += (word >> 4);
	word += (word >> 8);
	return word & 15;
}
#endif


#if 0
#else
#define DEBUG_ENT(fmt, arg...) do {} while (0)
#endif

struct entropy_store {
	/* mostly-read data: */
	struct poolinfo poolinfo;
	__u32 *pool;
	const char *name;

	/* read-write data: */
	spinlock_t lock ____cacheline_aligned_in_smp;
	unsigned add_ptr;
	int entropy_count;
	int input_rotate;
};

static void __add_entropy_words(struct entropy_store *r, const __u32 *in,
				int nwords, __u32 out[16])
{
	static __u32 const twist_table[8] = {
		0x00000000, 0x3b6e20c8, 0x76dc4190, 0x4db26158,
		0xedb88320, 0xd6d6a3e8, 0x9b64c2b0, 0xa00ae278 };
	unsigned long i, add_ptr, tap1, tap2, tap3, tap4, tap5;
	int new_rotate, input_rotate;
	int wordmask = r->poolinfo.poolwords - 1;
	__u32 w, next_w;
	unsigned long flags;

	/* Taps are constant, so we can load them without holding r->lock.  */
	tap1 = r->poolinfo.tap1;
	tap2 = r->poolinfo.tap2;
	tap3 = r->poolinfo.tap3;
	tap4 = r->poolinfo.tap4;
	tap5 = r->poolinfo.tap5;
	next_w = *in++;

	spin_lock_irqsave(&r->lock, flags);
	prefetch_range(r->pool, wordmask);
	input_rotate = r->input_rotate;
	add_ptr = r->add_ptr;

	while (nwords--) {
		w = rotate_left(input_rotate, next_w);
		if (nwords > 0)
			next_w = *in++;
		i = add_ptr = (add_ptr - 1) & wordmask;
		/*
		 * Normally, we add 7 bits of rotation to the pool.
		 * At the beginning of the pool, add an extra 7 bits
		 * rotation, so that successive passes spread the
		 * input bits across the pool evenly.
		 */
		new_rotate = input_rotate + 14;
		if (i)
			new_rotate = input_rotate + 7;
		input_rotate = new_rotate & 31;

		/* XOR in the various taps */
		w ^= r->pool[(i + tap1) & wordmask];
		w ^= r->pool[(i + tap2) & wordmask];
		w ^= r->pool[(i + tap3) & wordmask];
		w ^= r->pool[(i + tap4) & wordmask];
		w ^= r->pool[(i + tap5) & wordmask];
		w ^= r->pool[i];
		r->pool[i] = (w >> 3) ^ twist_table[w & 7];
	}

	r->input_rotate = input_rotate;
	r->add_ptr = add_ptr;

	if (out) {
		for (i = 0; i < 16; i++) {
			out[i] = r->pool[add_ptr];
			add_ptr = (add_ptr - 1) & wordmask;
		}
	}

	spin_unlock_irqrestore(&r->lock, flags);
}

static inline void add_entropy_words(struct entropy_store *r, const __u32 *in,
				     int nwords)
{
	__add_entropy_words(r, in, nwords, NULL);
}

/*
 * Credit (or debit) the entropy store with n bits of entropy
 */
static void credit_entropy_store(struct entropy_store *r, int nbits)
{
	unsigned long flags;

	spin_lock_irqsave(&r->lock, flags);

	if (r->entropy_count + nbits < 0) {
		DEBUG_ENT("negative entropy/overflow (%d+%d)\n",
			  r->entropy_count, nbits);
		r->entropy_count = 0;
	} else if (r->entropy_count + nbits > r->poolinfo.POOLBITS) {
		r->entropy_count = r->poolinfo.POOLBITS;
	} else {
		r->entropy_count += nbits;
		if (nbits)
			DEBUG_ENT("added %d entropy credits to %s\n",
				  nbits, r->name);
	}

	spin_unlock_irqrestore(&r->lock, flags);
}

struct sample {
	__u32 data[2];
	int credit;
};

static struct sample *batch_entropy_pool, *batch_entropy_copy;
static int batch_head, batch_tail;
static DEFINE_SPINLOCK(batch_lock);

static int batch_max;
static void batch_entropy_process(void *private_);
static DECLARE_WORK(batch_work, batch_entropy_process, NULL);

/* note: the size must be a power of 2 */
static int __init batch_entropy_init(int size, struct entropy_store *r)
{
	batch_entropy_pool = kmalloc(size*sizeof(struct sample), GFP_KERNEL);
	if (!batch_entropy_pool)
		return -1;
	batch_entropy_copy = kmalloc(size*sizeof(struct sample), GFP_KERNEL);
	if (!batch_entropy_copy) {
		kfree(batch_entropy_pool);
		return -1;
	}
	batch_head = batch_tail = 0;
	batch_work.data = r;
	batch_max = size;
	return 0;
}

static void batch_entropy_store(u32 a, u32 b, int num)
{
	int new;
	unsigned long flags;

	if (!batch_max)
		return;

	spin_lock_irqsave(&batch_lock, flags);

	batch_entropy_pool[batch_head].data[0] = a;
	batch_entropy_pool[batch_head].data[1] = b;
	batch_entropy_pool[batch_head].credit = num;

	if (((batch_head - batch_tail) & (batch_max - 1)) >= (batch_max / 2))
		schedule_delayed_work(&batch_work, 1);

	new = (batch_head + 1) & (batch_max - 1);
	if (new == batch_tail)
		DEBUG_ENT("batch entropy buffer full\n");
	else
		batch_head = new;

	spin_unlock_irqrestore(&batch_lock, flags);
}

static void batch_entropy_process(void *private_)
{
	struct entropy_store *r	= (struct entropy_store *) private_, *p;
	int max_entropy = r->poolinfo.POOLBITS;
	unsigned head, tail;

	/* Mixing into the pool is expensive, so copy over the batch
	 * data and release the batch lock. The pool is at least half
	 * full, so don't worry too much about copying only the used
	 * part.
	 */
	spin_lock_irq(&batch_lock);

	memcpy(batch_entropy_copy, batch_entropy_pool,
	       batch_max * sizeof(struct sample));

	head = batch_head;
	tail = batch_tail;
	batch_tail = batch_head;

	spin_unlock_irq(&batch_lock);

	p = r;
	while (head != tail) {
		if (r->entropy_count >= max_entropy) {
			r = (r == sec_random_state) ? random_state :
				sec_random_state;
			max_entropy = r->poolinfo.POOLBITS;
		}
		add_entropy_words(r, batch_entropy_copy[tail].data, 2);
		credit_entropy_store(r, batch_entropy_copy[tail].credit);
		tail = (tail + 1) & (batch_max - 1);
	}
	if (p->entropy_count >= random_read_wakeup_thresh)
		wake_up_interruptible(&random_read_wait);
}

struct timer_rand_state {
	cycles_t last_time;
	long last_delta,last_delta2;
	unsigned dont_count_entropy:1;
};

static struct timer_rand_state input_timer_state;
static struct timer_rand_state extract_timer_state;
static struct timer_rand_state *irq_timer_state[NR_IRQS];

static void add_timer_randomness(struct timer_rand_state *state, unsigned num)
{
	cycles_t data;
	long delta, delta2, delta3, time;
	int entropy = 0;

	preempt_disable();
	/* if over the trickle threshold, use only 1 in 4096 samples */
	if (random_state->entropy_count > trickle_thresh &&
	    (__get_cpu_var(trickle_count)++ & 0xfff))
		goto out;

	/*
	 * Calculate number of bits of randomness we probably added.
	 * We take into account the first, second and third-order deltas
	 * in order to make our estimate.
	 */
	time = jiffies;

	if (!state->dont_count_entropy) {
		delta = time - state->last_time;
		state->last_time = time;

		delta2 = delta - state->last_delta;
		state->last_delta = delta;

		delta3 = delta2 - state->last_delta2;
		state->last_delta2 = delta2;

		if (delta < 0)
			delta = -delta;
		if (delta2 < 0)
			delta2 = -delta2;
		if (delta3 < 0)
			delta3 = -delta3;
		if (delta > delta2)
			delta = delta2;
		if (delta > delta3)
			delta = delta3;

		/*
		 * delta is now minimum absolute delta.
		 * Round down by 1 bit on general principles,
		 * and limit entropy entimate to 12 bits.
		 */
		delta >>= 1;
		delta &= (1 << 12) - 1;

		entropy = int_ln_12bits(delta);
	}

	/*
	 * Use get_cycles() if implemented, otherwise fall back to
	 * jiffies.
	 */
	data = get_cycles();
	if (data)
		num ^= (u32)((data >> 31) >> 1);
	else
		data = time;

	batch_entropy_store(num, data, entropy);
out:
	preempt_enable();
}

void add_interrupt_randomness(int irq) {
    panic("in add_interrupt_randomness");
}

void add_disk_randomness(struct gendisk *disk)
{
	if (!disk || !disk->random)
		return;
	/* first major is 1, so we get >= 0x200 here */
	DEBUG_ENT("disk event %d:%d\n", disk->major, disk->first_minor);

	add_timer_randomness(disk->random,
			     0x100 + MKDEV(disk->major, disk->first_minor));
}

EXPORT_SYMBOL(add_disk_randomness);

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