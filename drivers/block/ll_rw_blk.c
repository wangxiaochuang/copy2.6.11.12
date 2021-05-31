#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/bootmem.h>	/* for max_pfn/max_low_pfn */
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/writeback.h>

/*
 * for max sense size
 */
#include <scsi/scsi_cmnd.h>

static kmem_cache_t *iocontext_cachep;

long blk_congestion_wait(int rw, long timeout)
{
    return 0;
}

void put_io_context(struct io_context *ioc)
{
	if (ioc == NULL)
		return;

	BUG_ON(atomic_read(&ioc->refcount) == 0);

	if (atomic_dec_and_test(&ioc->refcount)) {
		if (ioc->aic && ioc->aic->dtor)
			ioc->aic->dtor(ioc->aic);
		if (ioc->cic && ioc->cic->dtor)
			ioc->cic->dtor(ioc->cic);

		kmem_cache_free(iocontext_cachep, ioc);
	}
}
EXPORT_SYMBOL(put_io_context);

/* Called by the exitting task */
void exit_io_context(void)
{
	unsigned long flags;
	struct io_context *ioc;

	local_irq_save(flags);
	ioc = current->io_context;
	current->io_context = NULL;
	local_irq_restore(flags);

	if (ioc->aic && ioc->aic->exit)
		ioc->aic->exit(ioc->aic);
	if (ioc->cic && ioc->cic->exit)
		ioc->cic->exit(ioc->cic);

	put_io_context(ioc);
}