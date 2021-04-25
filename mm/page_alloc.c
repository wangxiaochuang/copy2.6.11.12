#include <linux/config.h>
#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/topology.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/nodemask.h>
#include <linux/vmalloc.h>

#include <asm/tlbflush.h>
#include "internal.h"

nodemask_t node_online_map = { { [0] = 1UL } };
struct pglist_data *pgdat_list;
unsigned long totalram_pages;
unsigned long totalhigh_pages;
long nr_swap_pages;

/*
 * Used by page_zone() to look up the address of the struct zone whose
 * id is encoded in the upper bits of page->flags
 */
struct zone *zone_table[1 << (ZONES_SHIFT + NODES_SHIFT)];
EXPORT_SYMBOL(zone_table);

static char *zone_names[MAX_NR_ZONES] = { "DMA", "Normal", "HighMem" };

unsigned long __initdata nr_kernel_pages;
unsigned long __initdata nr_all_pages;

/*
 * Temporary debugging check for pages not lying within a given zone.
 */
static int bad_range(struct zone *zone, struct page *page)
{
	if (page_to_pfn(page) >= zone->zone_start_pfn + zone->spanned_pages)
		return 1;
	if (page_to_pfn(page) < zone->zone_start_pfn)
		return 1;
#ifdef CONFIG_HOLES_IN_ZONE
	if (!pfn_valid(page_to_pfn(page)))
		return 1;
#endif
	if (zone != page_zone(page))
		return 1;
	return 0;
}

static void bad_page(const char *function, struct page *page)
{
	printk(KERN_EMERG "Bad page state at %s (in process '%s', page %p)\n",
		function, current->comm, page);
	printk(KERN_EMERG "flags:0x%0*lx mapping:%p mapcount:%d count:%d\n",
		(int)(2*sizeof(page_flags_t)), (unsigned long)page->flags,
		page->mapping, page_mapcount(page), page_count(page));
	printk(KERN_EMERG "Backtrace:\n");
	dump_stack();
	printk(KERN_EMERG "Trying to fix it up, but a reboot is needed\n");
	page->flags &= ~(1 << PG_private	|
			1 << PG_locked	|
			1 << PG_lru	|
			1 << PG_active	|
			1 << PG_dirty	|
			1 << PG_swapcache |
			1 << PG_writeback);
	set_page_count(page, 0);
	reset_page_mapcount(page);
	page->mapping = NULL;
	tainted |= TAINT_BAD_PAGE;
}

#ifndef CONFIG_HUGETLB_PAGE
#error "!CONFIG_HUGETLB_PAGE"
#else
static void destroy_compound_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;

	if (!PageCompound(page))
		return;

	if (page[1].index != order)
		bad_page(__FUNCTION__, page);

	for (i = 0; i < nr_pages; i++) {
		struct page *p = page + i;

		if (!PageCompound(p))
			bad_page(__FUNCTION__, page);
		if (p->private != (unsigned long)page)
			bad_page(__FUNCTION__, page);
		ClearPageCompound(p);
	}
}
#endif

/*
 * function for dealing with page's order in buddy system.
 * zone->lock is already acquired when we use these.
 * So, we don't need atomic page->flags operations here.
 */
static inline unsigned long page_order(struct page *page) {
	return page->private;
}

static inline void set_page_order(struct page *page, int order) {
	page->private = order;
	__SetPagePrivate(page);
}

static inline void rmv_page_order(struct page *page)
{
	__ClearPagePrivate(page);
	page->private = 0;
}

static inline int page_is_buddy(struct page *page, int order)
{
       if (PagePrivate(page)           &&
           (page_order(page) == order) &&
           !PageReserved(page)         &&
            page_count(page) == 0)
               return 1;
       return 0;
}

static inline void __free_pages_bulk (struct page *page, struct page *base,
		struct zone *zone, unsigned int order)
{
	unsigned long page_idx;
	struct page *coalesced;
	int order_size = 1 << order;

	if (unlikely(order))
		destroy_compound_page(page, order);

	page_idx = page - base;

	BUG_ON(page_idx & (order_size - 1));
	BUG_ON(bad_range(zone, page));

	zone->free_pages += order_size;
	while (order < MAX_ORDER - 1) {
		struct free_area *area;
		struct page *buddy;
		int buddy_idx;

		buddy_idx = (page_idx ^ (1 << order));
		buddy = base + buddy_idx;
		if (bad_range(zone, buddy))
			break;
		if (!page_is_buddy(buddy, order))
			break;
		list_del(&buddy->lru);
		area = zone->free_area + order;
		area->nr_free--;
		rmv_page_order(buddy);
		page_idx &= buddy_idx;
		order++;
	}
	coalesced = base + page_idx;
	set_page_order(coalesced, order);
	list_add(&coalesced->lru, &zone->free_area[order].free_list);
	zone->free_area[order].nr_free++;
}

static inline void free_pages_check(const char *function, struct page *page)
{
	if (	page_mapped(page) ||
		page->mapping != NULL ||
		page_count(page) != 0 ||
		(page->flags & (
			1 << PG_lru	|
			1 << PG_private |
			1 << PG_locked	|
			1 << PG_active	|
			1 << PG_reclaim	|
			1 << PG_slab	|
			1 << PG_swapcache |
			1 << PG_writeback )))
		bad_page(function, page);
	if (PageDirty(page))
		ClearPageDirty(page);
}

/*
 * Frees a list of pages. 
 * Assumes all pages on list are in same zone, and of same order.
 * count is the number of pages to free, or 0 for all on the list.
 *
 * If the zone was previously in an "all pages pinned" state then look to
 * see if this freeing clears that state.
 *
 * And clear the zone's pages_scanned counter, to hold off the "all pages are
 * pinned" detection logic.
 */
static int
free_pages_bulk(struct zone *zone, int count,
		struct list_head *list, unsigned int order)
{
	unsigned long flags;
	struct page *base, *page = NULL;
	int ret = 0;

	base = zone->zone_mem_map;
	spin_lock_irqsave(&zone->lock, flags);
	zone->all_unreclaimable = 0;
	zone->pages_scanned = 0;
	while (!list_empty(list) && count--) {
		page = list_entry(list->prev, struct page, lru);
		list_del(&page->lru);
		__free_pages_bulk(page, base, zone, order);
		ret++;
	}
	spin_unlock_irqrestore(&zone->lock, flags);
	return ret;
}


void __free_pages_ok(struct page *page, unsigned int order) {
	LIST_HEAD(list);
	int i;

	arch_free_page(page, order);

	mod_page_state(pgfree, 1 << order);

#ifndef CONFIG_MMU
	if (order > 0)
		for (i = 1 ; i < (1 << order) ; ++i)
			__put_page(page + i);
#endif

	for (i = 0 ; i < (1 << order) ; ++i)
		free_pages_check(__FUNCTION__, page + i);
	list_add(&page->lru, &list);
	kernel_map_pages(page, 1<<order, 0);
	free_pages_bulk(page_zone(page), 1, &list, order);
}


void set_page_refs(struct page *page, int order)
{
#ifdef CONFIG_MMU
	set_page_count(page, 1);
#else
#error "!CONFIG_MMU"
#endif /* CONFIG_MMU */
}

/*
 * Free a 0-order page
 */
static void FASTCALL(free_hot_cold_page(struct page *page, int cold));
static void fastcall free_hot_cold_page(struct page *page, int cold) {
	struct zone *zone = page_zone(page);
	struct per_cpu_pages *pcp;
	unsigned long flags;

	arch_free_page(page, 0);
	kernel_map_pages(page, 1, 0);
	inc_page_state(pgfree);
	if (PageAnon(page))
		page->mapping = NULL;
	free_pages_check(__FUNCTION__, page);
	pcp = &zone->pageset[get_cpu()].pcp[cold];
	local_irq_save(flags);
	if (pcp->count > pcp->high)
		pcp->count -= free_pages_bulk(zone, pcp->batch, &pcp->list, 0);
	list_add(&page->lru, &pcp->list);
	pcp->count++;
	local_irq_restore(flags);
	put_cpu();
}

void fastcall free_hot_page(struct page *page)
{
	free_hot_cold_page(page, 0);
}
	
void fastcall free_cold_page(struct page *page)
{
	free_hot_cold_page(page, 1);
}


fastcall unsigned long __get_free_pages(unsigned int gfp_mask, unsigned int order)
{
	return 0;
}

EXPORT_SYMBOL(__get_free_pages);

fastcall void __free_pages(struct page *page, unsigned int order)
{
	if (!PageReserved(page) && put_page_testzero(page)) {
		if (order == 0)
			free_hot_page(page);
		else
			__free_pages_ok(page, order);
	}
}

EXPORT_SYMBOL(__free_pages);

fastcall void free_pages(unsigned long addr, unsigned int order)
{
	if (addr != 0) {
		BUG_ON(!virt_addr_valid((void *)addr));
		__free_pages(virt_to_page((void *)addr), order);
	}
}

EXPORT_SYMBOL(free_pages);

/*
 * Total amount of free (allocatable) RAM:
 */
unsigned int nr_free_pages(void)
{
	unsigned int sum = 0;
	struct zone *zone;

	for_each_zone(zone)
		sum += zone->free_pages;

	return sum;
}

EXPORT_SYMBOL(nr_free_pages);

/*
 * Accumulate the page_state information across all CPUs.
 * The result is unavoidably approximate - it can change
 * during and after execution of this function.
 */
static DEFINE_PER_CPU(struct page_state, page_states) = {0};

void __mod_page_state(unsigned offset, unsigned long delta)
{
	unsigned long flags;
	void* ptr;

	local_irq_save(flags);
	ptr = &__get_cpu_var(page_states);
	*(unsigned long *)(ptr + offset) += delta;
	local_irq_restore(flags);
}

/*
 * Builds allocation fallback zone lists.
 */
static int __init build_zonelists_node(pg_data_t *pgdat, struct zonelist *zonelist, int j, int k)
{
	switch (k) {
		struct zone *zone;
	default:
		BUG();
	case ZONE_HIGHMEM:
		zone = pgdat->node_zones + ZONE_HIGHMEM;
		if (zone->present_pages) {
#ifndef CONFIG_HIGHMEM
			BUG();
#endif
			zonelist->zones[j++] = zone;
		}
	case ZONE_NORMAL:
		zone = pgdat->node_zones + ZONE_NORMAL;
		if (zone->present_pages)
			zonelist->zones[j++] = zone;
	case ZONE_DMA:
		zone = pgdat->node_zones + ZONE_DMA;
		if (zone->present_pages)
			zonelist->zones[j++] = zone;
	}
	return j;
}

#ifdef CONFIG_NUMA
#error "CONFIG_NUMA"
#else /* CONFIG_NUMA */
static void __init build_zonelists(pg_data_t *pgdat) {
	int i, j, k, node, local_node;

	local_node = pgdat->node_id;

	for (i = 0; i < GFP_ZONETYPES; i++) {
		struct zonelist *zonelist;	

		zonelist = pgdat->node_zonelists + i;
		memset(zonelist, 0, sizeof(*zonelist));

		j = 0;
		k = ZONE_NORMAL;
		if (i & __GFP_HIGHMEM)
			k = ZONE_HIGHMEM;
		if (i & __GFP_DMA)
			k = ZONE_DMA;

		j = build_zonelists_node(pgdat, zonelist, j, k);

		for (node = local_node + 1; node < MAX_NUMNODES; node++) {
			if (!node_online(node))
				continue;
			j = build_zonelists_node(NODE_DATA(node), zonelist, j, k);
		}
		for (node = 0; node < local_node; node++) {
			if (!node_online(node))
				continue;
			j = build_zonelists_node(NODE_DATA(node), zonelist, j, k);
		}
		zonelist->zones[j] = NULL;
	}
}
#endif

void __init build_all_zonelists(void) {
	int i;

	for_each_online_node(i)
		build_zonelists(NODE_DATA(i));
	printk("Built %i zonelists\n", num_online_nodes());
}

#define PAGES_PER_WAITQUEUE	256

static inline unsigned long wait_table_size(unsigned long pages) {
	unsigned long size = 1;

	pages /= PAGES_PER_WAITQUEUE;

	while (size < pages)
		size <<= 1;

	size = min(size, 4096UL);

	return max(size, 4UL);
}

/*
 * This is an integer logarithm so that shifts can be used later
 * to extract the more random high bits from the multiplicative
 * hash function before the remainder is taken.
 */
static inline unsigned long wait_table_bits(unsigned long size) {
	return ffz(~size);
}

static void __init calculate_zone_totalpages(struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long *zholes_size) {
    unsigned long realtotalpages, totalpages = 0;
	int i;

	for (i = 0; i < MAX_NR_ZONES; i++)
		totalpages += zones_size[i];
	pgdat->node_spanned_pages = totalpages;

	realtotalpages = totalpages;
	if (zholes_size)
		for (i = 0; i < MAX_NR_ZONES; i++)
			realtotalpages -= zholes_size[i];
	pgdat->node_present_pages = realtotalpages;
	printk(KERN_DEBUG "On node %d totalpages: %lu\n", pgdat->node_id, realtotalpages);
}

/*
 * Initially all pages are reserved - free ones are freed
 * up by free_all_bootmem() once the early boot process is
 * done. Non-atomic initialization, single-pass.
 * 这里初始化的是nid节点的zone的memmap，memmap整个节点共享
 */
void __init memmap_init_zone(unsigned long size, int nid, unsigned long zone,
		unsigned long start_pfn) {
    struct page *start = pfn_to_page(start_pfn);
	struct page *page;

	for (page = start; page < (start + size); page++) {
		// 设置page的flags位图
		set_page_zone(page, NODEZONE(nid, zone));
		set_page_count(page, 0);
		reset_page_mapcount(page);
		SetPageReserved(page);
		INIT_LIST_HEAD(&page->lru);
#ifdef WANT_PAGE_VIRTUAL
#error "WANT_PAGE_VIRTUAL"
#endif
		start_pfn++;
	}
}

void zone_init_free_lists(struct pglist_data *pgdat, struct zone *zone,
				unsigned long size)
{
	int order;
	for (order = 0; order < MAX_ORDER; order++) {
		INIT_LIST_HEAD(&zone->free_area[order].free_list);
		zone->free_area[order].nr_free = 0;
	}
}

#ifndef __HAVE_ARCH_MEMMAP_INIT
#define memmap_init(size, nid, zone, start_pfn) \
	memmap_init_zone((size), (nid), (zone), (start_pfn))
#endif

/*
 * Set up the zone data structures:
 *   - mark all pages reserved
 *   - mark all memory queues empty
 *   - clear the memory bitmaps
 */
static void __init free_area_init_core(struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long *zholes_size) {
    unsigned long i, j;
	const unsigned long zone_required_alignment = 1UL << (MAX_ORDER - 1);
	int cpu, nid = pgdat->node_id;
	unsigned long zone_start_pfn = pgdat->node_start_pfn;

	pgdat->nr_zones = 0;
	init_waitqueue_head(&pgdat->kswapd_wait);
	pgdat->kswapd_max_order = 0;

	for (j = 0; j < MAX_NR_ZONES; j++) {
		struct zone *zone = pgdat->node_zones + j;
		unsigned long size, realsize;
		unsigned long batch;

		zone_table[NODEZONE(nid, j)] = zone;
		realsize = size = zones_size[j];
		if (zholes_size)
			realsize -= zholes_size[j];

		if (j == ZONE_DMA || j == ZONE_NORMAL)
			nr_kernel_pages += realsize;
		nr_all_pages += realsize;	

		zone->spanned_pages = size;
		zone->present_pages = realsize;
		zone->name = zone_names[j];
		spin_lock_init(&zone->lock);
		spin_lock_init(&zone->lru_lock);
		zone->zone_pgdat = pgdat;
		zone->free_pages = 0;

		zone->temp_priority = zone->prev_priority = DEF_PRIORITY;

		batch = zone->present_pages / 1024;
		if (batch * PAGE_SIZE > 256 * 1024)
			batch = (256 * 1024) / PAGE_SIZE;
		batch /= 4;
		if (batch < 1)
			batch = 1;
		for (cpu = 0; cpu < NR_CPUS; cpu++) {
			struct per_cpu_pages *pcp;

			pcp = &zone->pageset[cpu].pcp[0];		/* hot */
			pcp->count = 0;
			pcp->low = 2 * batch;
			pcp->high = 6 * batch;
			pcp->batch = 1 * batch;
			INIT_LIST_HEAD(&pcp->list);

			pcp = &zone->pageset[cpu].pcp[1];		/* cold */
			pcp->count = 0;
			pcp->low = 0;
			pcp->high = 2 * batch;
			pcp->batch = 1 * batch;
			INIT_LIST_HEAD(&pcp->list);
		}
		printk(KERN_DEBUG "  %s zone: %lu pages, LIFO batch:%lu\n",
				zone_names[j], realsize, batch);
		INIT_LIST_HEAD(&zone->active_list);
		INIT_LIST_HEAD(&zone->inactive_list);
		zone->nr_scan_active = 0;
		zone->nr_scan_inactive = 0;
		zone->nr_active = 0;
		zone->nr_inactive = 0;
		if (!size)
			continue;
		/*
		 * The per-page waitqueue mechanism uses hashed waitqueues
		 * per zone.
		 */	
		zone->wait_table_size = wait_table_size(size);
		zone->wait_table_bits = 
			wait_table_bits(zone->wait_table_size);
		zone->wait_table = (wait_queue_head_t *)
			alloc_bootmem_node(pgdat, zone->wait_table_size
						* sizeof(wait_queue_head_t));

		for (i = 0; i < zone->wait_table_size; ++i)
			init_waitqueue_head(zone->wait_table + i);

		pgdat->nr_zones = j + 1;

		zone->zone_mem_map = pfn_to_page(zone_start_pfn);
		zone->zone_start_pfn = zone_start_pfn;

		if ((zone_start_pfn) & (zone_required_alignment-1))
			printk(KERN_CRIT "BUG: wrong zone alignment, it will crash\n");

		memmap_init(size, nid, j, zone_start_pfn);

		zone_start_pfn += size;

		zone_init_free_lists(pgdat, zone, zone->spanned_pages);
	}
}

void __init node_alloc_mem_map(struct pglist_data *pgdat) {
	unsigned long size;

	size = (pgdat->node_spanned_pages + 1) * sizeof(struct page);
	pgdat->node_mem_map = alloc_bootmem_node(pgdat, size);
#ifndef CONFIG_DISCONTIGMEM
	mem_map = contig_page_data.node_mem_map;
#endif
}

void __init free_area_init_node(int nid, struct pglist_data *pgdat,
		unsigned long *zones_size, unsigned long node_start_pfn,
		unsigned long *zholes_size) {
    pgdat->node_id = nid;
	pgdat->node_start_pfn = node_start_pfn;
	calculate_zone_totalpages(pgdat, zones_size, zholes_size);

	if (!pfn_to_page(node_start_pfn))
		node_alloc_mem_map(pgdat);

	free_area_init_core(pgdat, zones_size, zholes_size);
}

#ifndef CONFIG_DISCONTIGMEM
static bootmem_data_t contig_bootmem_data;
struct pglist_data contig_page_data = { .bdata = &contig_bootmem_data };

EXPORT_SYMBOL(contig_page_data);

void __init free_area_init(unsigned long *zones_size)
{
	free_area_init_node(0, &contig_page_data, zones_size,
			__pa(PAGE_OFFSET) >> PAGE_SHIFT, NULL);
}
#endif

void __init page_alloc_init(void)
{
	hotcpu_notifier(page_alloc_cpu_notify, 0);
}

__initdata int hashdist = HASHDIST_DEFAULT;

/*
 * allocate a large system hash table from bootmem
 * - it is assumed that the hash table must contain an exact power-of-2
 *   quantity of entries
 * - limit is the number of hash buckets, not the total allocation size
 */
void *__init alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long limit)
{
	unsigned long long max = limit;
	unsigned long log2qty, size;
	void *table = NULL;

	if (!numentries) {
		numentries = (flags & HASH_HIGHMEM) ? nr_all_pages : nr_kernel_pages;
		numentries += (1UL << (20 - PAGE_SHIFT)) - 1;
		numentries >>= 20 - PAGE_SHIFT;
		numentries <<= 20 - PAGE_SHIFT;

		/* limit to 1 bucket per 2^scale bytes of low memory */
		if (scale > PAGE_SHIFT)
			numentries >>= (scale - PAGE_SHIFT);
		else
			numentries <<= (PAGE_SHIFT - scale);
	}
	/* rounded up to nearest power of 2 in size */
	numentries = 1UL << (long_log2(numentries) + 1);

	/* limit allocation size to 1/16 total memory by default */
	if (max == 0) {
		max = ((unsigned long long)nr_all_pages << PAGE_SHIFT) >> 4;
		do_div(max, bucketsize);
	}

	if (numentries > max)
		numentries = max;

	log2qty = long_log2(numentries);

	do {
		size = bucketsize << log2qty;
		if (flags & HASH_EARLY)
			table = alloc_bootmem(size);
		else if (hashdist)
			mypanic("page_alloc.c 1");
		else {
			mypanic("page_alloc.c 2");
		}
	} while (!table && size > PAGE_SIZE && --log2qty);

	if (!table)
		panic("Failed to allocate %s hash table\n", tablename);

	printk("%s hash table entries: %d (order: %d, %lu bytes)\n",
	       tablename,
	       (1U << log2qty),
	       long_log2(size) - PAGE_SHIFT,
	       size);

	if (_hash_shift)
		*_hash_shift = log2qty;
	if (_hash_mask)
		*_hash_mask = (1 << log2qty) - 1;

	return table;
}