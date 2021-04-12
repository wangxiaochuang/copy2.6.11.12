#include <linux/mm.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#include <linux/vmalloc.h>

#include <asm/uaccess.h>
#include <asm/tlbflush.h>

DEFINE_RWLOCK(vmlist_lock);
struct vm_struct *vmlist;

#define IOREMAP_MAX_ORDER	(7 + PAGE_SHIFT)	/* 128 pages */

struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
				unsigned long start, unsigned long end) {
    struct vm_struct **p, *tmp, *area;
	unsigned long align = 1;
	unsigned long addr;

	if (flags & VM_IOREMAP) {
		int bit = fls(size);

		if (bit > IOREMAP_MAX_ORDER)
			bit = IOREMAP_MAX_ORDER;
		else if (bit < PAGE_SHIFT)
			bit = PAGE_SHIFT;
		align = 1ul << bit;
	}
	addr = ALIGN(start, align);

	area = kmalloc(sizeof(*area), GFP_KERNEL);
	if (unlikely(!area))
		return NULL;

	/*
	 * We always allocate a guard page.
	 */
	size += PAGE_SIZE;
	if (unlikely(!size)) {
		kfree(area);
		return NULL;
	}

	write_lock(&vmlist_lock);
	for (p = &vmlist; (tmp = *p) != NULL; p = &tmp->next) {
		if ((unsigned long)tmp->addr < addr) {
			if ((unsigned long)tmp->addr + tmp->size >= addr)
				addr = ALIGN(tmp->size + (unsigned long)tmp->addr, align);
			continue;
		}
		if ((size + addr) < addr)
			goto out;
		if (size + addr <= (unsigned long)tmp->addr)
			goto found;
		// 要分配的地址的终点在大于tmp的addr，只有往上寻找
		addr = ALIGN(tmp->size + (unsigned long)tmp->addr, align);
		if (addr > end - size)
			goto out;
	}

found:
	area->next = *p;
	*p = area;

	area->flags = flags;
	area->addr = (void *)addr;
	area->size = size;
	area->pages = NULL;
	area->nr_pages = 0;
	area->phys_addr = 0;
	write_unlock(&vmlist_lock);

	return area;

out:
	write_unlock(&vmlist_lock);
	kfree(area);
	if (printk_ratelimit())
		printk(KERN_WARNING "allocation failed: out of vmalloc space - use vmalloc=<size> to increase size.\n");
	return NULL;
}

struct vm_struct *get_vm_area(unsigned long size, unsigned long flags) {
	return __get_vm_area(size, flags, VMALLOC_START, VMALLOC_END);
}

void __vunmap(void *addr, int deallocate_pages)
{
	struct vm_struct *area;

	if (!addr)
		return;
}

void vunmap(void *addr)
{
	BUG_ON(in_interrupt());
	__vunmap(addr, 0);
}

EXPORT_SYMBOL(vunmap);