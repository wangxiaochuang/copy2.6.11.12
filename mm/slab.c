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

void * kmem_cache_alloc (kmem_cache_t *cachep, int flags) {
    return NULL;
}

EXPORT_SYMBOL(kmem_cache_alloc);

void * __kmalloc (size_t size, int flags) {
    return NULL;
}

EXPORT_SYMBOL(__kmalloc);

void kfree (const void *objp) {

}

EXPORT_SYMBOL(kfree);