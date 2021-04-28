#ifndef TEST                        // to test in user space...
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module.h>
#endif
#include <linux/string.h>
#include <linux/idr.h>

static kmem_cache_t *idr_layer_cache;

static void idr_cache_ctor(void * idr_layer, 
			   kmem_cache_t *idr_layer_cache, unsigned long flags)
{
	memset(idr_layer, 0, sizeof(struct idr_layer));
}

static  int init_id_cache(void)
{
	if (!idr_layer_cache)
		idr_layer_cache = kmem_cache_create("idr_layer_cache", 
			sizeof(struct idr_layer), 0, 0, idr_cache_ctor, NULL);
	return 0;
}

/**
 * idr_init - initialize idr handle
 * @idp:	idr handle
 *
 * This function is use to set up the handle (@idp) that you will pass
 * to the rest of the functions.
 */
void idr_init(struct idr *idp) {
    init_id_cache();
    memset(idp, 0, sizeof(struct idr));
	spin_lock_init(&idp->lock);
}
EXPORT_SYMBOL(idr_init);