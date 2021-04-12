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

struct pglist_data *pgdat_list;

/*
 * Used by page_zone() to look up the address of the struct zone whose
 * id is encoded in the upper bits of page->flags
 */
struct zone *zone_table[1 << (ZONES_SHIFT + NODES_SHIFT)];
EXPORT_SYMBOL(zone_table);

static char *zone_names[MAX_NR_ZONES] = { "DMA", "Normal", "HighMem" };

unsigned long __initdata nr_kernel_pages;
unsigned long __initdata nr_all_pages;

fastcall unsigned long __get_free_pages(unsigned int gfp_mask, unsigned int order)
{
	return 0;
}

EXPORT_SYMBOL(__get_free_pages);

fastcall void __free_pages(struct page *page, unsigned int order)
{
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