#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#include <asm/dma.h>
#include <asm/io.h>
#include "internal.h"

/*
 * Access to this subsystem has to be serialized externally. (this is
 * true for the boot process anyway)
 */
unsigned long max_low_pfn;
unsigned long min_low_pfn;
unsigned long max_pfn;

EXPORT_SYMBOL(max_pfn);		/* This is exported so
				 * dma_get_required_mask(), which uses
				 * it, can be an inline function */

/*
 * Called once to set up the allocator itself.
 */
static unsigned long __init init_bootmem_core (pg_data_t *pgdat,
	unsigned long mapstart, unsigned long start, unsigned long end) {
	bootmem_data_t *bdata = pgdat->bdata;
	unsigned long mapsize = ((end - start) + 7) / 8;
	// 0 8176 1022
	// start end 是以4k为单位的，表示页，使用位图表示使用情况，所以mapsize是除以8的结果

	pgdat->pgdat_next = pgdat_list;
	pgdat_list = pgdat;

	// map有mapsize个字节，每个位表示8个页
	mapsize = (mapsize + (sizeof(long) - 1UL)) & ~(sizeof(long) - 1UL);
	// 可自由分配内存区域的前面放map
	bdata->node_bootmem_map = phys_to_virt(mapstart << PAGE_SHIFT);
	bdata->node_boot_start = (start << PAGE_SHIFT);
	bdata->node_low_pfn = end;

	memset(bdata->node_bootmem_map, 0xff, mapsize); // 初始化为1标识保留
	return mapsize;
}

static void __init reserve_bootmem_core(bootmem_data_t *bdata, unsigned long addr, unsigned long size) {
	unsigned long i;

	unsigned long sidx = (addr - bdata->node_boot_start) / PAGE_SIZE;
	unsigned long eidx = (addr + size - bdata->node_boot_start +
							PAGE_SIZE - 1) / PAGE_SIZE;
	unsigned long end = (addr + size + PAGE_SIZE - 1) / PAGE_SIZE;

	BUG_ON(!size);
	BUG_ON(sidx >= eidx);
	BUG_ON((addr >> PAGE_SHIFT) >= bdata->node_low_pfn);
	BUG_ON(end > bdata->node_low_pfn);

	for (i = sidx; i < eidx; i++)
		if (test_and_set_bit(i, bdata->node_bootmem_map)) {
#ifdef CONFIG_DEBUG_BOOTMEM
			printk("hm, page %08lx reserved twice.\n", i*PAGE_SIZE);
#endif
		}
}

// 将addr开始的size大小置为不可用状态
static void __init free_bootmem_core(bootmem_data_t *bdata, unsigned long addr, unsigned long size) {
	unsigned long i;
	unsigned long start;

	unsigned long sidx;
	unsigned long eidx = (addr + size - bdata->node_boot_start) / PAGE_SIZE;
	unsigned long end = (addr + size) / PAGE_SIZE;

	BUG_ON(!size);
	BUG_ON(end > bdata->node_low_pfn);

	if (addr < bdata->last_success)
		bdata->last_success = addr;

	start = (addr + PAGE_SIZE - 1) / PAGE_SIZE;
	sidx = start - (bdata->node_boot_start / PAGE_SIZE);

	for (i = sidx; i < eidx; i++) {
		if (unlikely(!test_and_clear_bit(i, bdata->node_bootmem_map)))
			BUG();
	}
}

static void * __init
__alloc_bootmem_core(struct bootmem_data *bdata, unsigned long size,
		unsigned long align, unsigned long goal) {
    unsigned long offset, remaining_size, areasize, preferred;
	unsigned long i, start = 0, incr, eidx;
	void *ret;

	if(!size) {
		printk("__alloc_bootmem_core(): zero-sized request\n");
		BUG();
	}
	BUG_ON(align & (align-1));

	eidx = bdata->node_low_pfn - (bdata->node_boot_start >> PAGE_SHIFT);
	offset = 0;
	if (align &&
	    (bdata->node_boot_start & (align - 1UL)) != 0)
		offset = (align - (bdata->node_boot_start & (align - 1UL)));
	offset >>= PAGE_SHIFT;

	/*
	 * We try to allocate bootmem pages above 'goal'
	 * first, then we try to allocate lower pages.
	 */
	if (goal && (goal >= bdata->node_boot_start) && 
	    ((goal >> PAGE_SHIFT) < bdata->node_low_pfn)) {
		preferred = goal - bdata->node_boot_start;

		if (bdata->last_success >= preferred)
			preferred = bdata->last_success;
	} else
		preferred = 0;

	preferred = ((preferred + align - 1) & ~(align - 1)) >> PAGE_SHIFT;
	preferred += offset;
	areasize = (size+PAGE_SIZE-1)/PAGE_SIZE;
	incr = align >> PAGE_SHIFT ? : 1;

restart_scan:
	for (i = preferred; i < eidx; i += incr) {
		unsigned long j;
		i = find_next_zero_bit(bdata->node_bootmem_map, eidx, i);
		i = ALIGN(i, incr);
		if (test_bit(i, bdata->node_bootmem_map)) {
			continue;
		}
		for (j = i + 1; j < i + areasize; ++j) {
			if (j >= eidx)
				goto fail_block;
			if (test_bit (j, bdata->node_bootmem_map))
				goto fail_block;
		}
		start = i;
		goto found;
	fail_block:
		i = ALIGN(j, incr);
	}

	if (preferred > offset) {
		preferred = offset;
		goto restart_scan;
	}
	return NULL;

found:
	bdata->last_success = start << PAGE_SHIFT;
	BUG_ON(start >= eidx);

	/*
	 * Is the next page of the previous allocation-end the start
	 * of this allocation's buffer? If yes then we can 'merge'
	 * the previous partial page with this allocation.
	 */
	if (align < PAGE_SIZE &&
	    bdata->last_offset && bdata->last_pos+1 == start) {
		offset = (bdata->last_offset+align-1) & ~(align-1);
		BUG_ON(offset > PAGE_SIZE);
		remaining_size = PAGE_SIZE-offset;
		if (size < remaining_size) {
			areasize = 0;
			/* last_pos unchanged */
			bdata->last_offset = offset+size;
			ret = phys_to_virt(bdata->last_pos*PAGE_SIZE + offset +
						bdata->node_boot_start);
		} else {
			remaining_size = size - remaining_size;
			areasize = (remaining_size+PAGE_SIZE-1)/PAGE_SIZE;
			ret = phys_to_virt(bdata->last_pos*PAGE_SIZE + offset +
						bdata->node_boot_start);
			bdata->last_pos = start+areasize-1;
			bdata->last_offset = remaining_size;
		}
		bdata->last_offset &= ~PAGE_MASK;
	} else {
		bdata->last_pos = start + areasize - 1;
		bdata->last_offset = size & ~PAGE_MASK;
		ret = phys_to_virt(start * PAGE_SIZE + bdata->node_boot_start);
	}

	/*
	 * Reserve the area now:
	 */
	for (i = start; i < start+areasize; i++)
		if (unlikely(test_and_set_bit(i, bdata->node_bootmem_map)))
			BUG();
	memset(ret, 0, size);
	return ret;
}

static unsigned long __init free_all_bootmem_core(pg_data_t *pgdat)
{
	struct page *page;
	bootmem_data_t *bdata = pgdat->bdata;
	unsigned long i, count, total = 0;
	unsigned long idx;
	unsigned long *map; 
	int gofast = 0;

	BUG_ON(!bdata->node_bootmem_map);

	count = 0;
	/* first extant page of the node */
	page = virt_to_page(phys_to_virt(bdata->node_boot_start));
	idx = bdata->node_low_pfn - (bdata->node_boot_start >> PAGE_SHIFT);
	map = bdata->node_bootmem_map;
	/* Check physaddr is O(LOG2(BITS_PER_LONG)) page aligned */
	if (bdata->node_boot_start == 0 ||
		ffs(bdata->node_boot_start) - PAGE_SHIFT > ffs(BITS_PER_LONG))
		gofast = 1;
	for (i = 0; i < idx; ) {
		unsigned long v = ~map[i / BITS_PER_LONG];
		if (gofast && v == ~0UL) {
			int j, order;

			count += BITS_PER_LONG;
			__ClearPageReserved(page);
			order = ffs(BITS_PER_LONG) - 1;
			set_page_refs(page, order);
			for (j = 1; j < BITS_PER_LONG; j++) {
				if (j + 16 < BITS_PER_LONG)
					prefetchw(page + j + 16);
				__ClearPageReserved(page + j);
			}
			__free_pages(page, order);
			i += BITS_PER_LONG;
			page += BITS_PER_LONG;
		} else if (v) {
			unsigned long m;
			for (m = 1; m && i < idx; m <<= 1, page++, i++) {
				if (v & m) {
					count++;
					__ClearPageReserved(page);
					set_page_refs(page, 0);
					__free_page(page);
				}
			}
		} else {
			i += BITS_PER_LONG;
			page += BITS_PER_LONG;
		}
	}
	total += count;


	/*
	 * Now free the allocator bitmap itself, it's not
	 * needed anymore:
	 */
	page = virt_to_page(bdata->node_bootmem_map);
	count = 0;
	for (i = 0; i < ((bdata->node_low_pfn - (bdata->node_boot_start >> PAGE_SHIFT)) / 8 + PAGE_SIZE - 1) / PAGE_SIZE; i++, page++) {
		count++;
		__ClearPageReserved(page);
		set_page_count(page, 1);
		__free_page(page);
	}
	total += count;
	bdata->node_bootmem_map = NULL;

	return total;
}

unsigned long __init init_bootmem (unsigned long start, unsigned long pages) {
	max_low_pfn = pages;
	min_low_pfn = start;
	return(init_bootmem_core(NODE_DATA(0), start, 0, pages));
}

#ifndef CONFIG_HAVE_ARCH_BOOTMEM_NODE
void __init reserve_bootmem (unsigned long addr, unsigned long size)
{
	reserve_bootmem_core(NODE_DATA(0)->bdata, addr, size);
}
#endif /* !CONFIG_HAVE_ARCH_BOOTMEM_NODE */

void __init free_bootmem (unsigned long addr, unsigned long size) {
	free_bootmem_core(NODE_DATA(0)->bdata, addr, size);
}

unsigned long __init free_all_bootmem (void)
{
	return(free_all_bootmem_core(NODE_DATA(0)));
}

void * __init __alloc_bootmem (unsigned long size, unsigned long align, unsigned long goal) {
	pg_data_t *pgdat = pgdat_list;
	void *ptr;

	for_each_pgdat(pgdat)
		if ((ptr = __alloc_bootmem_core(pgdat->bdata, size, align, goal)))
			return ptr;
	/*
	 * Whoops, we cannot satisfy the allocation request.
	 */
	printk(KERN_ALERT "bootmem alloc of %lu bytes failed!\n", size);
	mypanic("Out of memory");
	return NULL;
}

void * __init __alloc_bootmem_node (pg_data_t *pgdat, unsigned long size, unsigned long align, unsigned long goal) {
	void *ptr;

	ptr = __alloc_bootmem_core(pgdat->bdata, size, align, goal);
	if (ptr)
		return (ptr);
	return __alloc_bootmem(size, align, goal);
}