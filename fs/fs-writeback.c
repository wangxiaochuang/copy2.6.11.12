#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/buffer_head.h>

extern struct super_block *blockdev_superblock;

void __mark_inode_dirty(struct inode *inode, int flags)
{
	struct super_block *sb = inode->i_sb;

	if (flags & (I_DIRTY_SYNC | I_DIRTY_DATASYNC)) {
		if (sb->s_op->dirty_inode)
			sb->s_op->dirty_inode(inode);
	}

	smp_mb();

	/* avoid the locking if we can */
	if ((inode->i_state & flags) == flags)
		return;

	if (unlikely(block_dump)) {
		panic("in __mark_inode_dirty function");
	}

	spin_lock(&inode_lock);
	if ((inode->i_state & flags) != flags) {
		const int was_dirty = inode->i_state & I_DIRTY;

		inode->i_state |= flags;

		if (inode->i_state & I_LOCK)
			goto out;

		if (!S_ISBLK(inode->i_mode)) {
			if (hlist_unhashed(&inode->i_hash))
				goto out;
		}
		if (inode->i_state & (I_FREEING|I_CLEAR))
			goto out;

		if (!was_dirty) {
			inode->dirtied_when = jiffies;
			list_move(&inode->i_list, &sb->s_dirty);
		}
	}

out:
	spin_unlock(&inode_lock);
}

EXPORT_SYMBOL(__mark_inode_dirty);

static int write_inode(struct inode *inode, int sync)
{
	if (inode->i_sb->s_op->write_inode && !is_bad_inode(inode))
		return inode->i_sb->s_op->write_inode(inode, sync);
	return 0;
}

static int
__sync_single_inode(struct inode *inode, struct writeback_control *wbc)
{
	unsigned dirty;
	struct address_space *mapping = inode->i_mapping;
	struct super_block *sb = inode->i_sb;
	int wait = wbc->sync_mode == WB_SYNC_ALL;
	int ret;

	BUG_ON(inode->i_state & I_LOCK);

	/* Set I_LOCK, reset I_DIRTY */
	dirty = inode->i_state & I_DIRTY;
	inode->i_state |= I_LOCK;
	inode->i_state &= ~I_DIRTY;

	spin_unlock(&inode_lock);

	ret = do_writepages(mapping, wbc);

	/* Don't write the inode if only I_DIRTY_PAGES was set */
	if (dirty & (I_DIRTY_SYNC | I_DIRTY_DATASYNC)) {
		int err = write_inode(inode, wait);
		if (ret == 0)
			ret = err;
	}

	if (wait) {
		int err = filemap_fdatawait(mapping);
		if (ret == 0)
			ret = err;
	}

	spin_lock(&inode_lock);
	inode->i_state &= ~I_LOCK;
	if (!(inode->i_state & I_FREEING)) {
		if (!(inode->i_state & I_DIRTY) &&
		    mapping_tagged(mapping, PAGECACHE_TAG_DIRTY)) {
			/*
			 * We didn't write back all the pages.  nfs_writepages()
			 * sometimes bales out without doing anything. Redirty
			 * the inode.  It is still on sb->s_io.
			 */
			if (wbc->for_kupdate) {
				/*
				 * For the kupdate function we leave the inode
				 * at the head of sb_dirty so it will get more
				 * writeout as soon as the queue becomes
				 * uncongested.
				 */
				inode->i_state |= I_DIRTY_PAGES;
				list_move_tail(&inode->i_list, &sb->s_dirty);
			} else {
				/*
				 * Otherwise fully redirty the inode so that
				 * other inodes on this superblock will get some
				 * writeout.  Otherwise heavy writing to one
				 * file would indefinitely suspend writeout of
				 * all the other files.
				 */
				inode->i_state |= I_DIRTY_PAGES;
				inode->dirtied_when = jiffies;
				list_move(&inode->i_list, &sb->s_dirty);
			}
		} else if (inode->i_state & I_DIRTY) {
			/*
			 * Someone redirtied the inode while were writing back
			 * the pages.
			 */
			list_move(&inode->i_list, &sb->s_dirty);
		} else if (atomic_read(&inode->i_count)) {
			/*
			 * The inode is clean, inuse
			 */
			list_move(&inode->i_list, &inode_in_use);
		} else {
			/*
			 * The inode is clean, unused
			 */
			list_move(&inode->i_list, &inode_unused);
			inodes_stat.nr_unused++;
		}
	}
	wake_up_inode(inode);
	return ret;
}

/*
 * Write out an inode's dirty pages.  Called under inode_lock.
 */
static int
__writeback_single_inode(struct inode *inode,
			struct writeback_control *wbc)
{
	wait_queue_head_t *wqh;

	if ((wbc->sync_mode != WB_SYNC_ALL) && (inode->i_state & I_LOCK)) {
		list_move(&inode->i_list, &inode->i_sb->s_dirty);
		return 0;
	}

	/*
	 * It's a data-integrity sync.  We must wait.
	 */
	if (inode->i_state & I_LOCK) {
		DEFINE_WAIT_BIT(wq, &inode->i_state, __I_LOCK);

		wqh = bit_waitqueue(&inode->i_state, __I_LOCK);
		do {
			__iget(inode);
			spin_unlock(&inode_lock);
			__wait_on_bit(wqh, &wq, inode_wait,
							TASK_UNINTERRUPTIBLE);
			iput(inode);
			spin_lock(&inode_lock);
		} while (inode->i_state & I_LOCK);
	}
	return __sync_single_inode(inode, wbc);
}

static void
sync_sb_inodes(struct super_block *sb, struct writeback_control *wbc)
{
	const unsigned long start = jiffies;	/* livelock avoidance */

	if (!wbc->for_kupdate || list_empty(&sb->s_io))
		list_splice_init(&sb->s_dirty, &sb->s_io);

	while (!list_empty(&sb->s_io)) {
		struct inode *inode = list_entry(sb->s_io.prev,
						struct inode, i_list);
		struct address_space *mapping = inode->i_mapping;
		struct backing_dev_info *bdi = mapping->backing_dev_info;
		long pages_skipped;

		if (bdi->memory_backed) {
			list_move(&inode->i_list, &sb->s_dirty);
			if (sb == blockdev_superblock) {
				/*
				 * Dirty memory-backed blockdev: the ramdisk
				 * driver does this.  Skip just this inode
				 */
				continue;
			}
			/*
			 * Dirty memory-backed inode against a filesystem other
			 * than the kernel-internal bdev filesystem.  Skip the
			 * entire superblock.
			 */
			break;
		}

		if (wbc->nonblocking && bdi_write_congested(bdi)) {
			wbc->encountered_congestion = 1;
			if (sb != blockdev_superblock)
				break;		/* Skip a congested fs */
			list_move(&inode->i_list, &sb->s_dirty);
			continue;		/* Skip a congested blockdev */
		}

		if (wbc->bdi && bdi != wbc->bdi) {
			if (sb != blockdev_superblock)
				break;		/* fs has the wrong queue */
			list_move(&inode->i_list, &sb->s_dirty);
			continue;		/* blockdev has wrong queue */
		}

		/* Was this inode dirtied after sync_sb_inodes was called? */
		if (time_after(inode->dirtied_when, start))
			break;

		/* Was this inode dirtied too recently? */
		if (wbc->older_than_this && time_after(inode->dirtied_when,
						*wbc->older_than_this))
			break;

		/* Is another pdflush already flushing this queue? */
		if (current_is_pdflush() && !writeback_acquire(bdi))
			break;

		BUG_ON(inode->i_state & I_FREEING);
		__iget(inode);
		pages_skipped = wbc->pages_skipped;
		__writeback_single_inode(inode, wbc);
		if (wbc->sync_mode == WB_SYNC_HOLD) {
			inode->dirtied_when = jiffies;
			list_move(&inode->i_list, &sb->s_dirty);
		}
		if (current_is_pdflush())
			writeback_release(bdi);
		if (wbc->pages_skipped != pages_skipped) {
			/*
			 * writeback is not making progress due to locked
			 * buffers.  Skip this inode for now.
			 */
			list_move(&inode->i_list, &sb->s_dirty);
		}
		spin_unlock(&inode_lock);
		cond_resched();
		iput(inode);
		spin_lock(&inode_lock);
		if (wbc->nr_to_write <= 0)
			break;
	}
	return;		/* Leave any unwritten inodes on s_io */
}

void sync_inodes_sb(struct super_block *sb, int wait)
{
	struct writeback_control wbc = {
		.sync_mode	= wait ? WB_SYNC_ALL : WB_SYNC_HOLD,
	};
	unsigned long nr_dirty = read_page_state(nr_dirty);
	unsigned long nr_unstable = read_page_state(nr_unstable);

	wbc.nr_to_write = nr_dirty + nr_unstable +
			(inodes_stat.nr_inodes - inodes_stat.nr_unused) +
			nr_dirty + nr_unstable;
	wbc.nr_to_write += wbc.nr_to_write / 2;		/* Bit more for luck */
	spin_lock(&inode_lock);
	sync_sb_inodes(sb, &wbc);
	spin_unlock(&inode_lock);
}

int writeback_acquire(struct backing_dev_info *bdi)
{
	return !test_and_set_bit(BDI_pdflush, &bdi->state);
}

int writeback_in_progress(struct backing_dev_info *bdi)
{
	return test_bit(BDI_pdflush, &bdi->state);
}

void writeback_release(struct backing_dev_info *bdi)
{
	BUG_ON(!writeback_in_progress(bdi));
	clear_bit(BDI_pdflush, &bdi->state);
}