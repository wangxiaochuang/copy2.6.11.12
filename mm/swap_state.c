#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/backing-dev.h>

#include <asm/pgtable.h>

static struct address_space_operations swap_aops = {
	.writepage	= swap_writepage,
	.sync_page	= block_sync_page,
	.set_page_dirty	= __set_page_dirty_nobuffers,
};

static struct backing_dev_info swap_backing_dev_info = {
	.memory_backed	= 1,	/* Does not contribute to dirty memory */
	.unplug_io_fn	= swap_unplug_io_fn,
};

struct address_space swapper_space = {
	.page_tree	= RADIX_TREE_INIT(GFP_ATOMIC|__GFP_NOWARN),
	.tree_lock	= SPIN_LOCK_UNLOCKED,
	.a_ops		= &swap_aops,
	.i_mmap_nonlinear = LIST_HEAD_INIT(swapper_space.i_mmap_nonlinear),
	.backing_dev_info = &swap_backing_dev_info,
};
EXPORT_SYMBOL(swapper_space);