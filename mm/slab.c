#include	<linux/config.h>
#include	<linux/slab.h>
#include	<linux/mm.h>
#include	<linux/swap.h>
#include	<linux/cache.h>
#include	<linux/interrupt.h>
#include	<linux/init.h>
#include	<linux/compiler.h>
#include	<linux/seq_file.h>
#include	<linux/notifier.h>
#include	<linux/kallsyms.h>
#include	<linux/cpu.h>
#include	<linux/sysctl.h>
#include	<linux/module.h>
#include	<linux/rcupdate.h>

#include	<asm/uaccess.h>
#include	<asm/cacheflush.h>
#include	<asm/tlbflush.h>
#include	<asm/page.h>

/* Shouldn't this be in a header file somewhere? */
#define	BYTES_PER_WORD		sizeof(void *)

#ifndef ARCH_KMALLOC_MINALIGN
/*
 * Enforce a minimum alignment for the kmalloc caches.
 * Usually, the kmalloc caches are cache_line_size() aligned, except when
 * DEBUG and FORCED_DEBUG are enabled, then they are BYTES_PER_WORD aligned.
 * Some archs want to perform DMA into kmalloc caches and need a guaranteed
 * alignment larger than BYTES_PER_WORD. ARCH_KMALLOC_MINALIGN allows that.
 * Note that this flag disables some debug features.
 */
#define ARCH_KMALLOC_MINALIGN 0
#endif

#ifndef ARCH_SLAB_MINALIGN
/*
 * Enforce a minimum alignment for all caches.
 * Intended for archs that get misalignment faults even for BYTES_PER_WORD
 * aligned buffers. Includes ARCH_KMALLOC_MINALIGN.
 * If possible: Do not enable this flag for CONFIG_DEBUG_SLAB, it disables
 * some debug features.
 */
#define ARCH_SLAB_MINALIGN 0
#endif

#ifndef ARCH_KMALLOC_FLAGS
#define ARCH_KMALLOC_FLAGS SLAB_HWCACHE_ALIGN
#endif

/* Legal flag mask for kmem_cache_create(). */
#if DEBUG
#error "DEBUG"
#else
# define CREATE_MASK	(SLAB_HWCACHE_ALIGN | SLAB_NO_REAP | \
			 SLAB_CACHE_DMA | SLAB_MUST_HWCACHE_ALIGN | \
			 SLAB_RECLAIM_ACCOUNT | SLAB_PANIC | \
			 SLAB_DESTROY_BY_RCU)
#endif

#define BUFCTL_END	(((kmem_bufctl_t)(~0U))-0)
#define BUFCTL_FREE	(((kmem_bufctl_t)(~0U))-1)
#define	SLAB_LIMIT	(((kmem_bufctl_t)(~0U))-2)

static unsigned long offslab_limit;

/*
 * struct slab
 *
 * Manages the objs in a slab. Placed either at the beginning of mem allocated
 * for a slab, or allocated from an general cache.
 * Slabs are chained into three list: fully used, partial, fully free slabs.
 */
struct slab {
	struct list_head	list;
	unsigned long		colouroff;
	void			*s_mem;		/* including colour offset */
	unsigned int		inuse;		/* num of objs active in slab */
	kmem_bufctl_t		free;
};

struct slab_rcu {
	struct rcu_head		head;
	kmem_cache_t		*cachep;
	void			*addr;
};

struct array_cache {
	unsigned int avail;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int touched;
};

/* bootstrap: The caches do not work without cpuarrays anymore,
 * but the cpuarrays are allocated from the generic caches...
 */
#define BOOT_CPUCACHE_ENTRIES	1
struct arraycache_init {
	struct array_cache cache;
	void * entries[BOOT_CPUCACHE_ENTRIES];
};

struct kmem_list3 {
	struct list_head	slabs_partial;	/* partial list first, better asm code */
	struct list_head	slabs_full;
	struct list_head	slabs_free;
	unsigned long	free_objects;
	int		free_touched;
	unsigned long	next_reap;
	struct array_cache	*shared;
};

#define LIST3_INIT(parent) \
	{ \
		.slabs_full	= LIST_HEAD_INIT(parent.slabs_full), \
		.slabs_partial	= LIST_HEAD_INIT(parent.slabs_partial), \
		.slabs_free	= LIST_HEAD_INIT(parent.slabs_free) \
	}
#define list3_data(cachep) \
	(&(cachep)->lists)

/* NUMA: per-node */
#define list3_data_ptr(cachep, ptr) \
		list3_data(cachep)

/*
 * kmem_cache_t
 *
 * manages a cache.
 */
	
struct kmem_cache_s {
/* 1) per-cpu data, touched during every alloc/free */
	struct array_cache	*array[NR_CPUS];
	unsigned int		batchcount;
	unsigned int		limit;
/* 2) touched by every alloc & free from the backend */
	struct kmem_list3	lists;
	/* NUMA: kmem_3list_t	*nodelists[MAX_NUMNODES] */
	unsigned int		objsize;
	unsigned int	 	flags;	/* constant flags */
	unsigned int		num;	/* # of objs per slab */
	unsigned int		free_limit; /* upper limit of objects in the lists */
	spinlock_t		spinlock;

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	unsigned int		gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	unsigned int		gfpflags;

	size_t			colour;		/* cache colouring range */
	unsigned int		colour_off;	/* colour offset */
	unsigned int		colour_next;	/* cache colouring */
	kmem_cache_t		*slabp_cache;
	unsigned int		slab_size;
	unsigned int		dflags;		/* dynamic flags */

	/* constructor func */
	void (*ctor)(void *, kmem_cache_t *, unsigned long);

	/* de-constructor func */
	void (*dtor)(void *, kmem_cache_t *, unsigned long);

/* 4) cache creation/removal */
	const char		*name;
	struct list_head	next;

/* 5) statistics */
#if STATS
	unsigned long		num_active;
	unsigned long		num_allocations;
	unsigned long		high_mark;
	unsigned long		grown;
	unsigned long		reaped;
	unsigned long 		errors;
	unsigned long		max_freeable;
	unsigned long		node_allocs;
	atomic_t		allochit;
	atomic_t		allocmiss;
	atomic_t		freehit;
	atomic_t		freemiss;
#endif
#if DEBUG
	int			dbghead;
	int			reallen;
#endif
};

#define CFLGS_OFF_SLAB		(0x80000000UL)
#define	OFF_SLAB(x)	((x)->flags & CFLGS_OFF_SLAB)

#define BATCHREFILL_LIMIT	16
/* Optimization question: fewer reaps means less 
 * probability for unnessary cpucache drain/refill cycles.
 *
 * OTHO the cpuarrays can contain lots of objects,
 * which could lock up otherwise freeable slabs.
 */
#define REAPTIMEOUT_CPUC	(2*HZ)
#define REAPTIMEOUT_LIST3	(4*HZ)

#if STATS
#error "STATS"
#else
#define	STATS_INC_ACTIVE(x)	do { } while (0)
#define	STATS_DEC_ACTIVE(x)	do { } while (0)
#define	STATS_INC_ALLOCED(x)	do { } while (0)
#define	STATS_INC_GROWN(x)	do { } while (0)
#define	STATS_INC_REAPED(x)	do { } while (0)
#define	STATS_SET_HIGH(x)	do { } while (0)
#define	STATS_INC_ERR(x)	do { } while (0)
#define	STATS_INC_NODEALLOCS(x)	do { } while (0)
#define	STATS_SET_FREEABLE(x, i) \
				do { } while (0)

#define STATS_INC_ALLOCHIT(x)	do { } while (0)
#define STATS_INC_ALLOCMISS(x)	do { } while (0)
#define STATS_INC_FREEHIT(x)	do { } while (0)
#define STATS_INC_FREEMISS(x)	do { } while (0)
#endif

/*
 * Maximum size of an obj (in 2^order pages)
 * and absolute limit for the gfp order.
 */
#if defined(CONFIG_LARGE_ALLOCS)
#error "CONFIG_LARGE_ALLOCS"
#elif defined(CONFIG_MMU)
#define	MAX_OBJ_ORDER	5	/* 32 pages */
#define	MAX_GFP_ORDER	5	/* 32 pages */
#else
#error "!CONFIG_MMU"
#endif

/*
 * Do not go above this order unless 0 objects fit into the slab.
 */
#define	BREAK_GFP_ORDER_HI	1
#define	BREAK_GFP_ORDER_LO	0
static int slab_break_gfp_order = BREAK_GFP_ORDER_LO;

// p 502
/* Macros for storing/retrieving the cachep and or slab from the
 * global 'mem_map'. These are used to find the slab an obj belongs to.
 * With kfree(), these are used to find the cache which an obj belongs to.
 */
#define	SET_PAGE_CACHE(pg,x)  ((pg)->lru.next = (struct list_head *)(x))
#define	GET_PAGE_CACHE(pg)    ((kmem_cache_t *)(pg)->lru.next)
#define	SET_PAGE_SLAB(pg,x)   ((pg)->lru.prev = (struct list_head *)(x))
#define	GET_PAGE_SLAB(pg)     ((struct slab *)(pg)->lru.prev)

/* These are the default caches for kmalloc. Custom caches can have other sizes. */
struct cache_sizes malloc_sizes[] = {
#define CACHE(x) { .cs_size = (x) },
#include <linux/kmalloc_sizes.h>
	{ 0, }
#undef CACHE
};

EXPORT_SYMBOL(malloc_sizes);

/* Must match cache_sizes above. Out of line to keep cache footprint low. */
struct cache_names {
	char *name;
	char *name_dma;
};

static struct cache_names __initdata cache_names[] = {
#define CACHE(x) { .name = "size-" #x, .name_dma = "size-" #x "(DMA)" },
#include <linux/kmalloc_sizes.h>
	{ NULL, }
#undef CACHE
};

static struct arraycache_init initarray_cache __initdata =
	{ { 0, BOOT_CPUCACHE_ENTRIES, 1, 0} };
static struct arraycache_init initarray_generic =
	{ { 0, BOOT_CPUCACHE_ENTRIES, 1, 0} };

/* internal cache of cache description objs */
static kmem_cache_t cache_cache = {
	.lists		= LIST3_INIT(cache_cache.lists),
	.batchcount	= 1,
	.limit		= BOOT_CPUCACHE_ENTRIES,
	.objsize	= sizeof(kmem_cache_t),
	.flags		= SLAB_NO_REAP,
	.spinlock	= SPIN_LOCK_UNLOCKED,
	.name		= "kmem_cache",
#if DEBUG
	.reallen	= sizeof(kmem_cache_t),
#endif
};

/* Guard access to the cache-chain. */
static struct semaphore	cache_chain_sem;
static struct list_head cache_chain;

/*
 * vm_enough_memory() looks at this to determine how many
 * slab-allocated pages are possibly freeable under pressure
 *
 * SLAB_RECLAIM_ACCOUNT turns this on per-slab
 */
atomic_t slab_reclaim_pages;
EXPORT_SYMBOL(slab_reclaim_pages);

/*
 * chicken and egg problem: delay the per-cpu array allocation
 * until the general caches are up.
 */
static enum {
	NONE,
	PARTIAL,
	FULL
} g_cpucache_up;

static DEFINE_PER_CPU(struct work_struct, reap_work);

static void free_block(kmem_cache_t* cachep, void** objpp, int len);
static void enable_cpucache (kmem_cache_t *cachep);
static void cache_reap (void *unused);

static inline void ** ac_entry(struct array_cache *ac)
{
	return (void**)(ac+1);
}

static inline struct array_cache *ac_data(kmem_cache_t *cachep)
{
	return cachep->array[smp_processor_id()];
}

static kmem_cache_t * kmem_find_general_cachep (size_t size, int gfpflags)
{
	struct cache_sizes *csizep = malloc_sizes;

	/* This function could be moved to the header file, and
	 * made inline so consumers can quickly determine what
	 * cache pointer they require.
	 */
	for ( ; csizep->cs_size; csizep++) {
		if (size > csizep->cs_size)
			continue;
		break;
	}
	return (gfpflags & GFP_DMA) ? csizep->cs_dmacachep : csizep->cs_cachep;
}

/* Cal the num objs, wastage, and bytes left over for a given slab size. */
static void cache_estimate (unsigned long gfporder, size_t size, size_t align,
		 int flags, size_t *left_over, unsigned int *num)
{
	int i;
	size_t wastage = PAGE_SIZE<<gfporder;
	size_t extra = 0;
	size_t base = 0;

	if (!(flags & CFLGS_OFF_SLAB)) {
		base = sizeof(struct slab);
		extra = sizeof(kmem_bufctl_t);
	}
	i = 0;
	while (i*size + ALIGN(base+i*extra, align) <= wastage)
		i++;
	if (i > 0)
		i--;

	if (i > SLAB_LIMIT)
		i = SLAB_LIMIT;

	*num = i;
	wastage -= i*size;
	wastage -= ALIGN(base+i*extra, align);
	*left_over = wastage;
}

#define slab_error(cachep, msg) __slab_error(__FUNCTION__, cachep, msg)

static void __slab_error(const char *function, kmem_cache_t *cachep, char *msg)
{
	printk(KERN_ERR "slab error in %s(): cache `%s': %s\n",
		function, cachep->name, msg);
	dump_stack();
}

static void __devinit start_cpu_timer(int cpu)
{
	struct work_struct *reap_work = &per_cpu(reap_work, cpu);

	/*
	 * When this gets called from do_initcalls via cpucache_init(),
	 * init_workqueues() has already run, so keventd will be setup
	 * at that time.
	 */
	if (keventd_up() && reap_work->func == NULL) {
		INIT_WORK(reap_work, cache_reap, NULL);
		schedule_delayed_work_on(cpu, reap_work, HZ + 3 * cpu);
	}
}

static struct array_cache *alloc_arraycache(int cpu, int entries, int batchcount)
{
	int memsize = sizeof(void *) * entries + sizeof(struct array_cache);
	struct array_cache *nc = NULL;

	if (cpu != -1) {
		nc = kmem_cache_alloc_node(kmem_find_general_cachep(memsize,
					GFP_KERNEL), cpu_to_node(cpu));
	}
	if (!nc)
		nc = kmalloc(memsize, GFP_KERNEL);
	if (nc) {
		nc->avail = 0;
		nc->limit = entries;
		nc->batchcount = batchcount;
		nc->touched = 0;
	}
	return nc;
}

static int __devinit cpuup_callback(struct notifier_block *nfb,
				  unsigned long action,
				  void *hcpu)
{
	long cpu = (long)hcpu;
	kmem_cache_t* cachep;

	switch (action) {
	case CPU_UP_PREPARE:
		down(&cache_chain_sem);
		list_for_each_entry(cachep, &cache_chain, next) {
			struct array_cache *nc;

			nc = alloc_arraycache(cpu, cachep->limit, cachep->batchcount);
			if (!nc)
				goto bad;

			spin_lock_irq(&cachep->spinlock);
			cachep->array[cpu] = nc;
			cachep->free_limit = (1+num_online_cpus())*cachep->batchcount
						+ cachep->num;
			spin_unlock_irq(&cachep->spinlock);

		}
		up(&cache_chain_sem);
		break;
	case CPU_ONLINE:
		start_cpu_timer(cpu);
		break;
#ifdef CONFIG_HOTPLUG_CPU
#error "CONFIG_HOTPLUG_CPU"
#endif
	}
	return NOTIFY_OK;
bad:
	up(&cache_chain_sem);
	return NOTIFY_BAD;
}

static struct notifier_block cpucache_notifier = { &cpuup_callback, NULL, 0 };

/* Initialisation. https://blog.csdn.net/rockrockwu/article/details/79976833
 * Called after the gfp() functions have been enabled, and before smp_init().
 */
void __init kmem_cache_init(void)
{
	size_t left_over;
	struct cache_sizes *sizes;
	struct cache_names *names;

	if (num_physpages > (32 << 20) >> PAGE_SHIFT)
		slab_break_gfp_order = BREAK_GFP_ORDER_HI;

	/* 1) create the cache_cache */
	init_MUTEX(&cache_chain_sem);
	INIT_LIST_HEAD(&cache_chain);
	list_add(&cache_cache.next, &cache_chain);
	cache_cache.colour_off = cache_line_size();
	cache_cache.array[smp_processor_id()] = &initarray_cache.cache;

	cache_cache.objsize = ALIGN(cache_cache.objsize, cache_line_size());

	cache_estimate(0, cache_cache.objsize, cache_line_size(), 0,
				&left_over, &cache_cache.num);
	if (!cache_cache.num)
		BUG();

	cache_cache.colour = left_over/cache_cache.colour_off;
	cache_cache.colour_next = 0;
	cache_cache.slab_size = ALIGN(cache_cache.num*sizeof(kmem_bufctl_t) +
				sizeof(struct slab), cache_line_size());

	/* 2+3) create the kmalloc caches */
	sizes = malloc_sizes;
	names = cache_names;

	while (sizes->cs_size) {
		/* For performance, all the general caches are L1 aligned.
		 * This should be particularly beneficial on SMP boxes, as it
		 * eliminates "false sharing".
		 * Note for systems short on memory removing the alignment will
		 * allow tighter packing of the smaller caches. */
		sizes->cs_cachep = kmem_cache_create(names->name,
			sizes->cs_size, ARCH_KMALLOC_MINALIGN,
			(ARCH_KMALLOC_FLAGS | SLAB_PANIC), NULL, NULL);

		/* Inc off-slab bufctl limit until the ceiling is hit. */
		if (!(OFF_SLAB(sizes->cs_cachep))) {
			offslab_limit = sizes->cs_size-sizeof(struct slab);
			offslab_limit /= sizeof(kmem_bufctl_t);
		}

		sizes->cs_dmacachep = kmem_cache_create(names->name_dma,
			sizes->cs_size, ARCH_KMALLOC_MINALIGN,
			(ARCH_KMALLOC_FLAGS | SLAB_CACHE_DMA | SLAB_PANIC),
			NULL, NULL);

		sizes++;
		names++;
	}
	/* 4) Replace the bootstrap head arrays */
	{
		void * ptr;
		
		ptr = kmalloc(sizeof(struct arraycache_init), GFP_KERNEL);
		local_irq_disable();
		BUG_ON(ac_data(&cache_cache) != &initarray_cache.cache);
		memcpy(ptr, ac_data(&cache_cache), sizeof(struct arraycache_init));
		cache_cache.array[smp_processor_id()] = ptr;
		local_irq_enable();
	
		ptr = kmalloc(sizeof(struct arraycache_init), GFP_KERNEL);
		local_irq_disable();
		BUG_ON(ac_data(malloc_sizes[0].cs_cachep) != &initarray_generic.cache);
		memcpy(ptr, ac_data(malloc_sizes[0].cs_cachep),
				sizeof(struct arraycache_init));
		malloc_sizes[0].cs_cachep->array[smp_processor_id()] = ptr;
		local_irq_enable();
	}

	/* 5) resize the head arrays to their final sizes */
	{
		kmem_cache_t *cachep;
		down(&cache_chain_sem);
		list_for_each_entry(cachep, &cache_chain, next)
			enable_cpucache(cachep);
		up(&cache_chain_sem);
	}

	/* Done! */
	g_cpucache_up = FULL;

	/* Register a cpu startup notifier callback
	 * that initializes ac_data for all new cpus
	 */
	register_cpu_notifier(&cpucache_notifier);
	

	/* The reap timers are started later, with a module init call:
	 * That part of the kernel is not yet operational.
	 */
}

static int __init cpucache_init(void)
{
	return 0;
}

__initcall(cpucache_init);

static void *kmem_getpages(kmem_cache_t *cachep, int flags, int nodeid)
{
	struct page *page;
	void *addr;
	int i;

	flags |= cachep->gfpflags;
	if (likely(nodeid == -1)) {
		page = alloc_pages(flags, cachep->gfporder);
	} else {
		page = alloc_pages_node(nodeid, flags, cachep->gfporder);
	}
	if (!page)
		return NULL;
	addr = page_address(page);

	i = (1 << cachep->gfporder);
	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		atomic_add(i, &slab_reclaim_pages);
	add_page_state(nr_slab, i);
	while (i--) {
		SetPageSlab(page);
		page++;
	}
	return addr;
}

static void kmem_freepages(kmem_cache_t *cachep, void *addr)
{
	unsigned long i = (1<<cachep->gfporder);
	struct page *page = virt_to_page(addr);
	const unsigned long nr_freed = i;

	while (i--) {
		if (!TestClearPageSlab(page))
			BUG();
		page++;
	}
	sub_page_state(nr_slab, nr_freed);
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += nr_freed;
	free_pages((unsigned long)addr, cachep->gfporder);
	if (cachep->flags & SLAB_RECLAIM_ACCOUNT) 
		atomic_sub(1<<cachep->gfporder, &slab_reclaim_pages);
}

static void kmem_rcu_free(struct rcu_head *head)
{
	struct slab_rcu *slab_rcu = (struct slab_rcu *) head;
	kmem_cache_t *cachep = slab_rcu->cachep;

	kmem_freepages(cachep, slab_rcu->addr);
	if (OFF_SLAB(cachep))
		kmem_cache_free(cachep->slabp_cache, slab_rcu);
}

static void slab_destroy (kmem_cache_t *cachep, struct slab *slabp)
{
	void *addr = slabp->s_mem - slabp->colouroff;
#if DEBUG
#error "DEBUG != 0"
#else
	if (cachep->dtor) {
		int i;
		for (i = 0; i < cachep->num; i++) {
			void *objp = slabp->s_mem + cachep->objsize * i;
			(cachep->dtor)(objp, cachep, 0);
		}
	}
#endif

	if (unlikely(cachep->flags & SLAB_DESTROY_BY_RCU)) {
		struct slab_rcu *slab_rcu;

		slab_rcu = (struct slab_rcu *) slabp;
		slab_rcu->cachep = cachep;
		slab_rcu->addr = addr;
		call_rcu(&slab_rcu->head, kmem_rcu_free);
	} else {
		kmem_freepages(cachep, addr);
		if (OFF_SLAB(cachep))
			kmem_cache_free(cachep->slabp_cache, slabp);
	}
}

kmem_cache_t *
kmem_cache_create (const char *name, size_t size, size_t align,
	unsigned long flags, void (*ctor)(void*, kmem_cache_t *, unsigned long),
	void (*dtor)(void*, kmem_cache_t *, unsigned long))
{
	size_t left_over, slab_size, ralign;
	kmem_cache_t *cachep = NULL;

	/*
	 * Sanity checks... these are all serious usage bugs.
	 */
	if ((!name) ||
		in_interrupt() ||
		(size < BYTES_PER_WORD) ||
		(size > (1<<MAX_OBJ_ORDER)*PAGE_SIZE) ||
		(dtor && !ctor)) {
			printk(KERN_ERR "%s: Early error in slab %s\n",
					__FUNCTION__, name);
			BUG();
		}

	if (flags & SLAB_DESTROY_BY_RCU)
		BUG_ON(dtor);

	/*
	 * Always checks flags, a caller might be expecting debug
	 * support which isn't available.
	 */
	if (flags & ~CREATE_MASK)
		BUG();

	/* Check that size is in terms of words.  This is needed to avoid
	 * unaligned accesses for some archs when redzoning is used, and makes
	 * sure any on-slab bufctl's are also correctly aligned.
	 */
	if (size & (BYTES_PER_WORD-1)) {
		size += (BYTES_PER_WORD-1);
		size &= ~(BYTES_PER_WORD-1);
	}

	/* calculate out the final buffer alignment: */
	/* 1) arch recommendation: can be overridden for debug */
	if (flags & SLAB_HWCACHE_ALIGN) {
		/* Default alignment: as specified by the arch code.
		 * Except if an object is really small, then squeeze multiple
		 * objects into one cacheline.
		 */
		ralign = cache_line_size();
		while (size <= ralign/2)
			ralign /= 2;
	} else {
		ralign = BYTES_PER_WORD;
	}
	/* 2) arch mandated alignment: disables debug if necessary */
	if (ralign < ARCH_SLAB_MINALIGN) {
		ralign = ARCH_SLAB_MINALIGN;
		if (ralign > BYTES_PER_WORD)
			flags &= ~(SLAB_RED_ZONE|SLAB_STORE_USER);
	}
	/* 3) caller mandated alignment: disables debug if necessary */
	if (ralign < align) {
		ralign = align;
		if (ralign > BYTES_PER_WORD)
			flags &= ~(SLAB_RED_ZONE|SLAB_STORE_USER);
	}
	/* 4) Store it. Note that the debug code below can reduce
	 *    the alignment to BYTES_PER_WORD.
	 */
	align = ralign;

	/* Get cache's description obj. */
	cachep = (kmem_cache_t *) kmem_cache_alloc(&cache_cache, SLAB_KERNEL);
	if (!cachep)
		goto opps;
	memset(cachep, 0, sizeof(kmem_cache_t));


	/* Determine if the slab management is 'on' or 'off' slab. */
	if (size >= (PAGE_SIZE>>3))
		/*
		 * Size is large, assume best to place the slab management obj
		 * off-slab (should allow better packing of objs).
		 */
		flags |= CFLGS_OFF_SLAB;

	size = ALIGN(size, align);

	if ((flags & SLAB_RECLAIM_ACCOUNT) && size <= PAGE_SIZE) {
		/*
		 * A VFS-reclaimable slab tends to have most allocations
		 * as GFP_NOFS and we really don't want to have to be allocating
		 * higher-order pages when we are unable to shrink dcache.
		 */
		cachep->gfporder = 0;
		cache_estimate(cachep->gfporder, size, align, flags,
					&left_over, &cachep->num);
	} else {
		/*
		 * Calculate size (in pages) of slabs, and the num of objs per
		 * slab.  This could be made much more intelligent.  For now,
		 * try to avoid using high page-orders for slabs.  When the
		 * gfp() funcs are more friendly towards high-order requests,
		 * this should be changed.
		 */
		do {
			unsigned int break_flag = 0;
cal_wastage:
			cache_estimate(cachep->gfporder, size, align, flags,
						&left_over, &cachep->num);
			if (break_flag)
				break;
			if (cachep->gfporder >= MAX_GFP_ORDER)
				break;
			if (!cachep->num)
				goto next;
			if (flags & CFLGS_OFF_SLAB &&
					cachep->num > offslab_limit) {
				/* This num of objs will cause problems. */
				cachep->gfporder--;
				break_flag++;
				goto cal_wastage;
			}

			/*
			 * Large num of objs is good, but v. large slabs are
			 * currently bad for the gfp()s.
			 */
			if (cachep->gfporder >= slab_break_gfp_order)
				break;

			if ((left_over*8) <= (PAGE_SIZE<<cachep->gfporder))
				break;	/* Acceptable internal fragmentation. */
next:
			cachep->gfporder++;
		} while (1);
	}

	if (!cachep->num) {
		printk("kmem_cache_create: couldn't create cache %s.\n", name);
		kmem_cache_free(&cache_cache, cachep);
		cachep = NULL;
		goto opps;
	}
	slab_size = ALIGN(cachep->num*sizeof(kmem_bufctl_t)
				+ sizeof(struct slab), align);

	/*
	 * If the slab has been placed off-slab, and we have enough space then
	 * move it on-slab. This is at the expense of any extra colouring.
	 */
	if (flags & CFLGS_OFF_SLAB && left_over >= slab_size) {
		flags &= ~CFLGS_OFF_SLAB;
		left_over -= slab_size;
	}

	if (flags & CFLGS_OFF_SLAB) {
		/* really off slab. No need for manual alignment */
		slab_size = cachep->num*sizeof(kmem_bufctl_t)+sizeof(struct slab);
	}

	cachep->colour_off = cache_line_size();
	/* Offset must be a multiple of the alignment. */
	if (cachep->colour_off < align)
		cachep->colour_off = align;
	cachep->colour = left_over/cachep->colour_off;
	cachep->slab_size = slab_size;
	cachep->flags = flags;
	cachep->gfpflags = 0;
	if (flags & SLAB_CACHE_DMA)
		cachep->gfpflags |= GFP_DMA;
	spin_lock_init(&cachep->spinlock);
	cachep->objsize = size;
	/* NUMA */
	INIT_LIST_HEAD(&cachep->lists.slabs_full);
	INIT_LIST_HEAD(&cachep->lists.slabs_partial);
	INIT_LIST_HEAD(&cachep->lists.slabs_free);

	if (flags & CFLGS_OFF_SLAB)
		cachep->slabp_cache = kmem_find_general_cachep(slab_size,0);
	cachep->ctor = ctor;
	cachep->dtor = dtor;
	cachep->name = name;

	/* Don't let CPUs to come and go */
	lock_cpu_hotplug();

	if (g_cpucache_up == FULL) {
		enable_cpucache(cachep);
	} else {
		if (g_cpucache_up == NONE) {
			/* Note: the first kmem_cache_create must create
			 * the cache that's used by kmalloc(24), otherwise
			 * the creation of further caches will BUG().
			 */
			cachep->array[smp_processor_id()] = &initarray_generic.cache;
			g_cpucache_up = PARTIAL;
		} else {
			cachep->array[smp_processor_id()] = kmalloc(sizeof(struct arraycache_init),GFP_KERNEL);
		}
		BUG_ON(!ac_data(cachep));
		ac_data(cachep)->avail = 0;
		ac_data(cachep)->limit = BOOT_CPUCACHE_ENTRIES;
		ac_data(cachep)->batchcount = 1;
		ac_data(cachep)->touched = 0;
		cachep->batchcount = 1;
		cachep->limit = BOOT_CPUCACHE_ENTRIES;
		cachep->free_limit = (1+num_online_cpus())*cachep->batchcount
					+ cachep->num;
	} 

	cachep->lists.next_reap = jiffies + REAPTIMEOUT_LIST3 +
					((unsigned long)cachep)%REAPTIMEOUT_LIST3;

	/* Need the semaphore to access the chain. */
	down(&cache_chain_sem);
	{
		struct list_head *p;
		mm_segment_t old_fs;

		old_fs = get_fs();
		set_fs(KERNEL_DS);
		list_for_each(p, &cache_chain) {
			kmem_cache_t *pc = list_entry(p, kmem_cache_t, next);
			char tmp;
			/* This happens when the module gets unloaded and doesn't
			   destroy its slab cache and noone else reuses the vmalloc
			   area of the module. Print a warning. */
			if (__get_user(tmp,pc->name)) { 
				printk("SLAB: cache with size %d has lost its name\n", 
					pc->objsize); 
				continue; 
			} 	
			if (!strcmp(pc->name,name)) { 
				printk("kmem_cache_create: duplicate cache %s\n",name); 
				up(&cache_chain_sem); 
				unlock_cpu_hotplug();
				BUG(); 
			}	
		}
		set_fs(old_fs);
	}

	/* cache setup completed, link it into the list */
	list_add(&cachep->next, &cache_chain);
	up(&cache_chain_sem);
	unlock_cpu_hotplug();
opps:
	if (!cachep && (flags & SLAB_PANIC))
		panic("kmem_cache_create(): failed to create slab `%s'\n",
			name);
	return cachep;
}
EXPORT_SYMBOL(kmem_cache_create);

#if DEBUG
#else
#define check_irq_off()	do { } while(0)
#define check_irq_on()	do { } while(0)
#define check_spinlock_acquired(x) do { } while(0)
#endif

/*
 * Waits for all CPUs to execute func().
 */
static void smp_call_function_all_cpus(void (*func) (void *arg), void *arg)
{
	check_irq_on();
	preempt_disable();

	local_irq_disable();
	func(arg);
	local_irq_enable();

	if (smp_call_function(func, arg, 1, 1))
		BUG();

	preempt_enable();
}

#if DEBUG
#else
#define kfree_debugcheck(x) do { } while(0)
#define cache_free_debugcheck(x,objp,z) (objp)
#define check_slabp(x,y) do { } while(0)
#endif

static void drain_array_locked(kmem_cache_t* cachep,
				struct array_cache *ac, int force);

static void do_drain(void *arg)
{
	kmem_cache_t *cachep = (kmem_cache_t*)arg;
	struct array_cache *ac;

	check_irq_off();
	ac = ac_data(cachep);
	spin_lock(&cachep->spinlock);
	free_block(cachep, &ac_entry(ac)[0], ac->avail);
	spin_unlock(&cachep->spinlock);
	ac->avail = 0;
}

static void drain_cpu_caches(kmem_cache_t *cachep)
{
	smp_call_function_all_cpus(do_drain, cachep);
	check_irq_on();
	spin_lock_irq(&cachep->spinlock);
	if (cachep->lists.shared)
		drain_array_locked(cachep, cachep->lists.shared, 1);
	spin_unlock_irq(&cachep->spinlock);
}

static int __cache_shrink(kmem_cache_t *cachep)
{
	struct slab *slabp;
	int ret;

	drain_cpu_caches(cachep);

	check_irq_on();
	spin_lock_irq(&cachep->spinlock);

	for(;;) {
		struct list_head *p;

		p = cachep->lists.slabs_free.prev;
		if (p == &cachep->lists.slabs_free)
			break;

		slabp = list_entry(cachep->lists.slabs_free.prev, struct slab, list);
#if DEBUG
		if (slabp->inuse)
			BUG();
#endif
		list_del(&slabp->list);

		cachep->lists.free_objects -= cachep->num;
		spin_unlock_irq(&cachep->spinlock);
		slab_destroy(cachep, slabp);
		spin_lock_irq(&cachep->spinlock);
	}
	ret = !list_empty(&cachep->lists.slabs_full) ||
		!list_empty(&cachep->lists.slabs_partial);
	spin_unlock_irq(&cachep->spinlock);
	return ret;
}

int kmem_cache_destroy (kmem_cache_t * cachep)
{
	int i;

	if (!cachep || in_interrupt())
		BUG();

	/* Don't let CPUs to come and go */
	lock_cpu_hotplug();

	/* Find the cache in the chain of caches. */
	down(&cache_chain_sem);
	/*
	 * the chain is never empty, cache_cache is never destroyed
	 */
	list_del(&cachep->next);
	up(&cache_chain_sem);

	if (__cache_shrink(cachep)) {
		slab_error(cachep, "Can't free all objects");
		down(&cache_chain_sem);
		list_add(&cachep->next,&cache_chain);
		up(&cache_chain_sem);
		unlock_cpu_hotplug();
		return 1;
	}

	if (unlikely(cachep->flags & SLAB_DESTROY_BY_RCU))
		synchronize_kernel();

	for (i = 0; i < NR_CPUS; i++)
		kfree(cachep->array[i]);

	kfree(cachep->lists.shared);
	cachep->lists.shared = NULL;
	kmem_cache_free(&cache_cache, cachep);

	unlock_cpu_hotplug();

	return 0;
}

EXPORT_SYMBOL(kmem_cache_destroy);

/* Get the memory for a slab management obj. */
static struct slab* alloc_slabmgmt (kmem_cache_t *cachep,
			void *objp, int colour_off, int local_flags)
{
	struct slab *slabp;
	
	if (OFF_SLAB(cachep)) {
		/* Slab management obj is off-slab. */
		slabp = kmem_cache_alloc(cachep->slabp_cache, local_flags);
		if (!slabp)
			return NULL;
	} else {
		slabp = objp+colour_off;
		colour_off += cachep->slab_size;
	}
	slabp->inuse = 0;
	slabp->colouroff = colour_off;
	slabp->s_mem = objp+colour_off;

	return slabp;
}

static inline kmem_bufctl_t *slab_bufctl(struct slab *slabp)
{
	return (kmem_bufctl_t *)(slabp+1);
}

static void cache_init_objs (kmem_cache_t * cachep,
			struct slab * slabp, unsigned long ctor_flags)
{
	int i;

	for (i = 0; i < cachep->num; i++) {
		void* objp = slabp->s_mem+cachep->objsize*i;
#if DEBUG
#error "DEBUG"
#else
		if (cachep->ctor)
			cachep->ctor(objp, cachep, ctor_flags);
#endif
		slab_bufctl(slabp)[i] = i+1;
	}
	slab_bufctl(slabp)[i-1] = BUFCTL_END;
	slabp->free = 0;
}

static void kmem_flagcheck(kmem_cache_t *cachep, int flags)
{
	if (flags & SLAB_DMA) {
		if (!(cachep->gfpflags & GFP_DMA))
			BUG();
	} else {
		if (cachep->gfpflags & GFP_DMA)
			BUG();
	}
}

static void set_slab_attr(kmem_cache_t *cachep, struct slab *slabp, void *objp)
{
	int i;
	struct page *page;

	/* Nasty!!!!!! I hope this is OK. */
	i = 1 << cachep->gfporder;
	page = virt_to_page(objp);
	do {
		SET_PAGE_CACHE(page, cachep);
		SET_PAGE_SLAB(page, slabp);
		page++;
	} while (--i);
}

/*
 * Grow (by 1) the number of slabs within a cache.  This is called by
 * kmem_cache_alloc() when there are no active objs left in a cache.
 */
static int cache_grow (kmem_cache_t * cachep, int flags, int nodeid)
{
	struct slab	*slabp;
	void		*objp;
	size_t		 offset;
	int		 local_flags;
	unsigned long	 ctor_flags;

	/* Be lazy and only check for valid flags here,
 	 * keeping it out of the critical path in kmem_cache_alloc().
	 */
	if (flags & ~(SLAB_DMA|SLAB_LEVEL_MASK|SLAB_NO_GROW))
		BUG();
	if (flags & SLAB_NO_GROW)
		return 0;

	ctor_flags = SLAB_CTOR_CONSTRUCTOR;
	local_flags = (flags & SLAB_LEVEL_MASK);
	if (!(local_flags & __GFP_WAIT))
		/*
		 * Not allowed to sleep.  Need to tell a constructor about
		 * this - it might need to know...
		 */
		ctor_flags |= SLAB_CTOR_ATOMIC;

	/* About to mess with non-constant members - lock. */
	check_irq_off();
	spin_lock(&cachep->spinlock);

	/* Get colour for the slab, and cal the next value. */
	offset = cachep->colour_next;
	cachep->colour_next++;
	if (cachep->colour_next >= cachep->colour)
		cachep->colour_next = 0;
	offset *= cachep->colour_off;

	spin_unlock(&cachep->spinlock);

	if (local_flags & __GFP_WAIT)
		local_irq_enable();

	/*
	 * The test for missing atomic flag is performed here, rather than
	 * the more obvious place, simply to reduce the critical path length
	 * in kmem_cache_alloc(). If a caller is seriously mis-behaving they
	 * will eventually be caught here (where it matters).
	 */
	kmem_flagcheck(cachep, flags);


	/* Get mem for the objs. */
	if (!(objp = kmem_getpages(cachep, flags, nodeid)))
		goto failed;

	/* Get slab management. */
	if (!(slabp = alloc_slabmgmt(cachep, objp, offset, local_flags)))
		goto opps1;

	set_slab_attr(cachep, slabp, objp);

	cache_init_objs(cachep, slabp, ctor_flags);

	if (local_flags & __GFP_WAIT)
		local_irq_disable();
	check_irq_off();
	spin_lock(&cachep->spinlock);

	/* Make slab active. */
	list_add_tail(&slabp->list, &(list3_data(cachep)->slabs_free));
	STATS_INC_GROWN(cachep);
	list3_data(cachep)->free_objects += cachep->num;
	spin_unlock(&cachep->spinlock);
	return 1;
opps1:
	kmem_freepages(cachep, objp);
failed:
	if (local_flags & __GFP_WAIT)
		local_irq_disable();
	return 0;
}

static void* cache_alloc_refill(kmem_cache_t* cachep, int flags)
{
	int batchcount;
	struct kmem_list3 *l3;
	struct array_cache *ac;

	check_irq_off();
	ac = ac_data(cachep);	
retry:
	batchcount = ac->batchcount;
	if (!ac->touched && batchcount > BATCHREFILL_LIMIT) {
		/* if there was little recent activity on this
		 * cache, then perform only a partial refill.
		 * Otherwise we could generate refill bouncing.
		 */
		batchcount = BATCHREFILL_LIMIT;
	}
	l3 = list3_data(cachep);
	BUG_ON(ac->avail > 0);
	spin_lock(&cachep->spinlock);
	if (l3->shared) {
		struct array_cache *shared_array = l3->shared;
		if (shared_array->avail) {
			if (batchcount > shared_array->avail)
				batchcount = shared_array->avail;
			shared_array->avail -= batchcount;
			ac->avail = batchcount;
			memcpy(ac_entry(ac), &ac_entry(shared_array)[shared_array->avail],
					sizeof(void*)*batchcount);
			shared_array->touched = 1;
			goto alloc_done;
		}
	}
	while (batchcount > 0) {
		struct list_head *entry;
		struct slab *slabp;
		/* Get slab alloc is to come from. */
		entry = l3->slabs_partial.next;
		if (entry == &l3->slabs_partial) {
			l3->free_touched = 1;
			entry = l3->slabs_free.next;
			if (entry == &l3->slabs_free)
				goto must_grow;
		}

		slabp = list_entry(entry, struct slab, list);
		check_slabp(cachep, slabp);
		check_spinlock_acquired(cachep);
		while (slabp->inuse < cachep->num && batchcount--) {
			kmem_bufctl_t next;
			STATS_INC_ALLOCED(cachep);
			STATS_INC_ACTIVE(cachep);
			STATS_SET_HIGH(cachep);

			/* get obj pointer */
			ac_entry(ac)[ac->avail++] = slabp->s_mem + slabp->free*cachep->objsize;

			slabp->inuse++;
			next = slab_bufctl(slabp)[slabp->free];
#if DEBUG
			slab_bufctl(slabp)[slabp->free] = BUFCTL_FREE;
#endif
		       	slabp->free = next;
		}
		check_slabp(cachep, slabp);

		/* move slabp to correct slabp list: */
		list_del(&slabp->list);
		if (slabp->free == BUFCTL_END)
			list_add(&slabp->list, &l3->slabs_full);
		else
			list_add(&slabp->list, &l3->slabs_partial);
	}

must_grow:
	l3->free_objects -= ac->avail;
alloc_done:
	spin_unlock(&cachep->spinlock);

	if (unlikely(!ac->avail)) {
		int x;
		x = cache_grow(cachep, flags, -1);
		
		// cache_grow can reenable interrupts, then ac could change.
		ac = ac_data(cachep);
		if (!x && ac->avail == 0)	// no objects in sight? abort
			return NULL;

		if (!ac->avail)		// objects refilled by interrupt?
			goto retry;
	}
	ac->touched = 1;
	return ac_entry(ac)[--ac->avail];
}

static inline void
cache_alloc_debugcheck_before(kmem_cache_t *cachep, int flags)
{
	might_sleep_if(flags & __GFP_WAIT);
#if DEBUG
#error "DEBUG"
#endif
}

#if DEBUG
#error "DEBUG"
#else
#define cache_alloc_debugcheck_after(a,b,objp,d) (objp)
#endif

static inline void * __cache_alloc (kmem_cache_t *cachep, int flags)
{
	unsigned long save_flags;
	void* objp;
	struct array_cache *ac;

	cache_alloc_debugcheck_before(cachep, flags);

	local_irq_save(save_flags);
	ac = ac_data(cachep);
	if (likely(ac->avail)) {
		STATS_INC_ALLOCHIT(cachep);
		ac->touched = 1;
		objp = ac_entry(ac)[--ac->avail];
	} else {
		STATS_INC_ALLOCMISS(cachep);
		objp = cache_alloc_refill(cachep, flags);
	}
	local_irq_restore(save_flags);
	objp = cache_alloc_debugcheck_after(cachep, flags, objp, __builtin_return_address(0));
	return objp;
}

/* 
 * NUMA: different approach needed if the spinlock is moved into
 * the l3 structure
 */

static void free_block(kmem_cache_t *cachep, void **objpp, int nr_objects)
{
	int i;

	check_spinlock_acquired(cachep);

	/* NUMA: move add into loop */
	cachep->lists.free_objects += nr_objects;

	for (i = 0; i < nr_objects; i++) {
		void *objp = objpp[i];
		struct slab *slabp;
		unsigned int objnr;

		slabp = GET_PAGE_SLAB(virt_to_page(objp));
		list_del(&slabp->list);
		objnr = (objp - slabp->s_mem) / cachep->objsize;
		check_slabp(cachep, slabp);

		slab_bufctl(slabp)[objnr] = slabp->free;
		slabp->free = objnr;
		STATS_DEC_ACTIVE(cachep);
		slabp->inuse--;
		check_slabp(cachep, slabp);

		/* fixup slab chains */
		if (slabp->inuse == 0) {
			if (cachep->lists.free_objects > cachep->free_limit) {
				cachep->lists.free_objects -= cachep->num;
				slab_destroy(cachep, slabp);
			} else {
				list_add(&slabp->list,
				&list3_data_ptr(cachep, objp)->slabs_free);
			}
		} else {
			list_add_tail(&slabp->list,
				&list3_data_ptr(cachep, objp)->slabs_partial);
		}
	}
}

static void cache_flusharray (kmem_cache_t* cachep, struct array_cache *ac)
{
	int batchcount;

	batchcount = ac->batchcount;
	check_irq_off();
	spin_lock(&cachep->spinlock);
	if (cachep->lists.shared) {
		struct array_cache *shared_array = cachep->lists.shared;
		int max = shared_array->limit - shared_array->avail;
		if (max) {
			if (batchcount > max)
				batchcount = max;
			memcpy(&ac_entry(shared_array)[shared_array->avail],
					&ac_entry(ac)[0],
					sizeof(void*)*batchcount);
			shared_array->avail += batchcount;
			goto free_done;
		}
	}
	free_block(cachep, &ac_entry(ac)[0], batchcount);
free_done:
#if STATS
#error "STATS != 0"
#endif
	spin_unlock(&cachep->spinlock);
	ac->avail -= batchcount;
	memmove(&ac_entry(ac)[0], &ac_entry(ac)[batchcount],
			sizeof(void*)*ac->avail);
}

static inline void __cache_free (kmem_cache_t *cachep, void* objp)
{
	struct array_cache *ac = ac_data(cachep);

	check_irq_off();
	objp = cache_free_debugcheck(cachep, objp, __builtin_return_address(0));

	if (likely(ac->avail < ac->limit)) {
		STATS_INC_FREEHIT(cachep);
		ac_entry(ac)[ac->avail++] = objp;
		return;
	} else {
		STATS_INC_FREEMISS(cachep);
		cache_flusharray(cachep, ac);
		ac_entry(ac)[ac->avail++] = objp;
	}
}

void * kmem_cache_alloc (kmem_cache_t *cachep, int flags) {
	return __cache_alloc(cachep, flags);
}

EXPORT_SYMBOL(kmem_cache_alloc);

void * __kmalloc (size_t size, int flags) {
	struct cache_sizes *csizep = malloc_sizes;

	for (; csizep->cs_size; csizep++) {
		if (size > csizep->cs_size)
			continue;
		return __cache_alloc(flags & GFP_DMA ?
			 csizep->cs_dmacachep : csizep->cs_cachep, flags);
	}
	return NULL;
}

EXPORT_SYMBOL(__kmalloc);

/**
 * kmem_cache_free - Deallocate an object
 * @cachep: The cache the allocation was from.
 * @objp: The previously allocated object.
 *
 * Free an object which was previously allocated from this
 * cache.
 */
void kmem_cache_free (kmem_cache_t *cachep, void *objp)
{
	unsigned long flags;

	local_irq_save(flags);
	__cache_free(cachep, objp);
	local_irq_restore(flags);
}

EXPORT_SYMBOL(kmem_cache_free);

void kfree (const void *objp) {
    kmem_cache_t *c;
	unsigned long flags;

	if (!objp)
		return;
	local_irq_save(flags);
	// kfree_debugcheck(objp);
	c = GET_PAGE_CACHE(virt_to_page(objp));
	__cache_free(c, (void*)objp);
	local_irq_restore(flags);
}

EXPORT_SYMBOL(kfree);

struct ccupdate_struct {
	kmem_cache_t *cachep;
	struct array_cache *new[NR_CPUS];
};

static void do_ccupdate_local(void *info)
{
	struct ccupdate_struct *new = (struct ccupdate_struct *)info;
	struct array_cache *old;

	check_irq_off();
	old = ac_data(new->cachep);
	
	new->cachep->array[smp_processor_id()] = new->new[smp_processor_id()];
	new->new[smp_processor_id()] = old;
}

static int do_tune_cpucache (kmem_cache_t* cachep, int limit, int batchcount, int shared)
{
	struct ccupdate_struct new;
	struct array_cache *new_shared;
	int i;

	memset(&new.new,0,sizeof(new.new));
	for (i = 0; i < NR_CPUS; i++) {
		if (cpu_online(i)) {
			new.new[i] = alloc_arraycache(i, limit, batchcount);
			if (!new.new[i]) {
				for (i--; i >= 0; i--) kfree(new.new[i]);
				return -ENOMEM;
			}
		} else {
			new.new[i] = NULL;
		}
	}
	new.cachep = cachep;

	smp_call_function_all_cpus(do_ccupdate_local, (void *)&new);
	
	check_irq_on();
	spin_lock_irq(&cachep->spinlock);
	cachep->batchcount = batchcount;
	cachep->limit = limit;
	cachep->free_limit = (1+num_online_cpus())*cachep->batchcount + cachep->num;
	spin_unlock_irq(&cachep->spinlock);

	for (i = 0; i < NR_CPUS; i++) {
		struct array_cache *ccold = new.new[i];
		if (!ccold)
			continue;
		spin_lock_irq(&cachep->spinlock);
		free_block(cachep, ac_entry(ccold), ccold->avail);
		spin_unlock_irq(&cachep->spinlock);
		kfree(ccold);
	}
	new_shared = alloc_arraycache(-1, batchcount*shared, 0xbaadf00d);
	if (new_shared) {
		struct array_cache *old;

		spin_lock_irq(&cachep->spinlock);
		old = cachep->lists.shared;
		cachep->lists.shared = new_shared;
		if (old)
			free_block(cachep, ac_entry(old), old->avail);
		spin_unlock_irq(&cachep->spinlock);
		kfree(old);
	}

	return 0;
}

static void enable_cpucache (kmem_cache_t *cachep)
{
	int err;
	int limit, shared;

	/* The head array serves three purposes:
	 * - create a LIFO ordering, i.e. return objects that are cache-warm
	 * - reduce the number of spinlock operations.
	 * - reduce the number of linked list operations on the slab and 
	 *   bufctl chains: array operations are cheaper.
	 * The numbers are guessed, we should auto-tune as described by
	 * Bonwick.
	 */
	if (cachep->objsize > 131072)
		limit = 1;
	else if (cachep->objsize > PAGE_SIZE)
		limit = 8;
	else if (cachep->objsize > 1024)
		limit = 24;
	else if (cachep->objsize > 256)
		limit = 54;
	else
		limit = 120;

	/* Cpu bound tasks (e.g. network routing) can exhibit cpu bound
	 * allocation behaviour: Most allocs on one cpu, most free operations
	 * on another cpu. For these cases, an efficient object passing between
	 * cpus is necessary. This is provided by a shared array. The array
	 * replaces Bonwick's magazine layer.
	 * On uniprocessor, it's functionally equivalent (but less efficient)
	 * to a larger limit. Thus disabled by default.
	 */
	shared = 0;
#ifdef CONFIG_SMP
	if (cachep->objsize <= PAGE_SIZE)
		shared = 8;
#endif

#if DEBUG
	/* With debugging enabled, large batchcount lead to excessively
	 * long periods with disabled local interrupts. Limit the 
	 * batchcount
	 */
	if (limit > 32)
		limit = 32;
#endif
	err = do_tune_cpucache(cachep, limit, (limit+1)/2, shared);
	if (err)
		printk(KERN_ERR "enable_cpucache failed for %s, error %d.\n",
					cachep->name, -err);
}

static void drain_array_locked(kmem_cache_t *cachep,
				struct array_cache *ac, int force)
{
	int tofree;

	check_spinlock_acquired(cachep);
	if (ac->touched && !force) {
		ac->touched = 0;
	} else if (ac->avail) {
		tofree = force ? ac->avail : (ac->limit+4)/5;
		if (tofree > ac->avail) {
			tofree = (ac->avail+1)/2;
		}
		free_block(cachep, ac_entry(ac), tofree);
		ac->avail -= tofree;
		memmove(&ac_entry(ac)[0], &ac_entry(ac)[tofree],
					sizeof(void*)*ac->avail);
	}
}

static void cache_reap(void *unused)
{
}

ssize_t slabinfo_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *ppos)
{
	return 0;
}