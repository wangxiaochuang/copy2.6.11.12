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

// p 502
#define	GET_PAGE_CACHE(pg)    ((kmem_cache_t *)(pg)->lru.next) 

static inline void __cache_free (kmem_cache_t *cachep, void* objp)
{

}

void * kmem_cache_alloc (kmem_cache_t *cachep, int flags) {
	return NULL;
}

EXPORT_SYMBOL(kmem_cache_alloc);

void * __kmalloc (size_t size, int flags) {
    return NULL;
}

EXPORT_SYMBOL(__kmalloc);

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