#include <linux/smp_lock.h>
#include <linux/time.h>
#include <linux/highuid.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include "ext2.h"
#include "acl.h"

MODULE_AUTHOR("Remy Card and others");
MODULE_DESCRIPTION("Second Extended Filesystem");
MODULE_LICENSE("GPL");

static int ext2_update_inode(struct inode * inode, int do_sync);

static inline int ext2_inode_is_fast_symlink(struct inode *inode)
{
	int ea_blocks = EXT2_I(inode)->i_file_acl ?
		(inode->i_sb->s_blocksize >> 9) : 0;

	return (S_ISLNK(inode->i_mode) &&
		inode->i_blocks - ea_blocks == 0);
}

void ext2_delete_inode (struct inode * inode)
{
    panic("in ext2_delete_inode");
}

void ext2_discard_prealloc (struct inode * inode)
{
    panic("in ext2_discard_prealloc");
}

static int ext2_alloc_block (struct inode * inode, unsigned long goal, int *err)
{
    panic("in ext2_alloc_block");
    return 0;
}

typedef struct {
	__le32	*p;
	__le32	key;
	struct buffer_head *bh;
} Indirect;

static inline void add_chain(Indirect *p, struct buffer_head *bh, __le32 *v)
{
	p->key = *(p->p = v);
	p->bh = bh;
}

static inline int verify_chain(Indirect *from, Indirect *to)
{
	while (from <= to && from->key == *from->p)
		from++;
	return (from > to);
}

static int ext2_block_to_path(struct inode *inode,
			long i_block, int offsets[4], int *boundary)
{
    panic("in ext2_block_to_path");
    return 0;
}

static Indirect *ext2_get_branch(struct inode *inode,
				 int depth,
				 int *offsets,
				 Indirect chain[4],
				 int *err)
{
    panic("in ext2_get_branch");
    return NULL;
}

static unsigned long ext2_find_near(struct inode *inode, Indirect *ind)
{
	panic("in ext2_find_near");
	return 0;
}

static inline int ext2_find_goal(struct inode *inode,
				 long block,
				 Indirect chain[4],
				 Indirect *partial,
				 unsigned long *goal)
{
	panic("in ext2_find_goal");
	return 0;
}

static int ext2_alloc_branch(struct inode *inode,
			     int num,
			     unsigned long goal,
			     int *offsets,
			     Indirect *branch)
{
	panic("in ext2_alloc_branch");
	return 0;
}

static inline int ext2_splice_branch(struct inode *inode,
				     long block,
				     Indirect chain[4],
				     Indirect *where,
				     int num)
{
	panic("in ext2_splice_branch");
	return 0;
}

int ext2_get_block(struct inode *inode, sector_t iblock, struct buffer_head *bh_result, int create)
{
    panic("in ext2_get_block");
    return 0;
}

static int ext2_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, ext2_get_block, wbc);
}

static int ext2_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, ext2_get_block);
}

static int
ext2_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, ext2_get_block);
}

static int
ext2_prepare_write(struct file *file, struct page *page,
			unsigned from, unsigned to)
{
	return block_prepare_write(page,from,to,ext2_get_block);
}

static int
ext2_nobh_prepare_write(struct file *file, struct page *page,
			unsigned from, unsigned to)
{
	return nobh_prepare_write(page,from,to,ext2_get_block);
}

static sector_t ext2_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,ext2_get_block);
}

static int
ext2_get_blocks(struct inode *inode, sector_t iblock, unsigned long max_blocks,
			struct buffer_head *bh_result, int create)
{
	int ret;

	ret = ext2_get_block(inode, iblock, bh_result, create);
	if (ret == 0)
		bh_result->b_size = (1 << inode->i_blkbits);
	return ret;
}

static ssize_t
ext2_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
			loff_t offset, unsigned long nr_segs)
{
    panic("in ext2_direct_IO");
    return 0;
}

static int
ext2_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, ext2_get_block);
}

struct address_space_operations ext2_aops = {
	.readpage		= ext2_readpage,
	.readpages		= ext2_readpages,
	.writepage		= ext2_writepage,
	.sync_page		= block_sync_page,
	.prepare_write		= ext2_prepare_write,
	.commit_write		= generic_commit_write,
	.bmap			= ext2_bmap,
	.direct_IO		= ext2_direct_IO,
	.writepages		= ext2_writepages,
};

struct address_space_operations ext2_nobh_aops = {
	.readpage		= ext2_readpage,
	.readpages		= ext2_readpages,
	.writepage		= ext2_writepage,
	.sync_page		= block_sync_page,
	.prepare_write		= ext2_nobh_prepare_write,
	.commit_write		= nobh_commit_write,
	.bmap			= ext2_bmap,
	.direct_IO		= ext2_direct_IO,
	.writepages		= ext2_writepages,
};

static inline int all_zeroes(__le32 *p, __le32 *q)
{
	while (p < q)
		if (*p++)
			return 0;
	return 1;
}

static Indirect *ext2_find_shared(struct inode *inode,
				int depth,
				int offsets[4],
				Indirect chain[4],
				__le32 *top)
{
    panic("in ext2_find_shared");
    return NULL;
}

static inline void ext2_free_data(struct inode *inode, __le32 *p, __le32 *q)
{
	panic("in ext2_free_data");
}


static void ext2_free_branches(struct inode *inode, __le32 *p, __le32 *q, int depth)
{
	panic("in ext2_free_branches");
}

void ext2_truncate (struct inode * inode)
{
	panic("in ext2_truncate");
}

static struct ext2_inode *ext2_get_inode(struct super_block *sb, ino_t ino,
					struct buffer_head **p)
{
	struct buffer_head * bh;
	unsigned long block_group;
	unsigned long block;
	unsigned long offset;
	struct ext2_group_desc * gdp;

	*p = NULL;
	if ((ino != EXT2_ROOT_INO && ino < EXT2_FIRST_INO(sb)) ||
	    ino > le32_to_cpu(EXT2_SB(sb)->s_es->s_inodes_count))
		goto Einval;
	
	block_group = (ino - 1) / EXT2_INODES_PER_GROUP(sb);
	gdp = ext2_get_group_desc(sb, block_group, &bh);
	if (!gdp)
		goto Egdp;
	
	/*
	 * Figure out the offset within the block group inode table
	 */
	offset = ((ino - 1) % EXT2_INODES_PER_GROUP(sb)) * EXT2_INODE_SIZE(sb);
	block = le32_to_cpu(gdp->bg_inode_table) +
		(offset >> EXT2_BLOCK_SIZE_BITS(sb));
	if (!(bh = sb_bread(sb, block)))
		goto Eio;
	
	*p = bh;
	offset &= (EXT2_BLOCK_SIZE(sb) - 1);
	return (struct ext2_inode *) (bh->b_data + offset);

Einval:
	ext2_error(sb, "ext2_get_inode", "bad inode number: %lu",
		   (unsigned long) ino);
	return ERR_PTR(-EINVAL);
Eio:
	ext2_error(sb, "ext2_get_inode",
		   "unable to read inode block - inode=%lu, block=%lu",
		   (unsigned long) ino, block);
Egdp:
	return ERR_PTR(-EIO);
}


void ext2_set_inode_flags(struct inode *inode)
{
	unsigned int flags = EXT2_I(inode)->i_flags;

	inode->i_flags &= ~(S_SYNC|S_APPEND|S_IMMUTABLE|S_NOATIME|S_DIRSYNC);
	if (flags & EXT2_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & EXT2_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & EXT2_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & EXT2_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & EXT2_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
}

void ext2_read_inode (struct inode * inode)
{
    	struct ext2_inode_info *ei = EXT2_I(inode);
	ino_t ino = inode->i_ino;
	struct buffer_head * bh;
	struct ext2_inode * raw_inode = ext2_get_inode(inode->i_sb, ino, &bh);
	int n;
#ifdef CONFIG_EXT2_FS_POSIX_ACL
	ei->i_acl = EXT2_ACL_NOT_CACHED;
	ei->i_default_acl = EXT2_ACL_NOT_CACHED;
#endif
	if (IS_ERR(raw_inode))
 		goto bad_inode;

	inode->i_mode = le16_to_cpu(raw_inode->i_mode);
	inode->i_uid = (uid_t)le16_to_cpu(raw_inode->i_uid_low);
	inode->i_gid = (gid_t)le16_to_cpu(raw_inode->i_gid_low);
	if (!(test_opt (inode->i_sb, NO_UID32))) {
		inode->i_uid |= le16_to_cpu(raw_inode->i_uid_high) << 16;
		inode->i_gid |= le16_to_cpu(raw_inode->i_gid_high) << 16;
	}
	inode->i_nlink = le16_to_cpu(raw_inode->i_links_count);
	inode->i_size = le32_to_cpu(raw_inode->i_size);
	inode->i_atime.tv_sec = le32_to_cpu(raw_inode->i_atime);
	inode->i_ctime.tv_sec = le32_to_cpu(raw_inode->i_ctime);
	inode->i_mtime.tv_sec = le32_to_cpu(raw_inode->i_mtime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec = 0;
	ei->i_dtime = le32_to_cpu(raw_inode->i_dtime);
	/* We now have enough fields to check if the inode was active or not.
	 * This is needed because nfsd might try to access dead inodes
	 * the test is that same one that e2fsck uses
	 * NeilBrown 1999oct15
	 */
	if (inode->i_nlink == 0 && (inode->i_mode == 0 || ei->i_dtime)) {
		/* this inode is deleted */
		brelse (bh);
		goto bad_inode;
	}
	inode->i_blksize = PAGE_SIZE;	/* This is the optimal IO size (for stat), not the fs block size */
	inode->i_blocks = le32_to_cpu(raw_inode->i_blocks);
	ei->i_flags = le32_to_cpu(raw_inode->i_flags);
	ei->i_faddr = le32_to_cpu(raw_inode->i_faddr);
	ei->i_frag_no = raw_inode->i_frag;
	ei->i_frag_size = raw_inode->i_fsize;
	ei->i_file_acl = le32_to_cpu(raw_inode->i_file_acl);
	ei->i_dir_acl = 0;
	if (S_ISREG(inode->i_mode))
		inode->i_size |= ((__u64)le32_to_cpu(raw_inode->i_size_high)) << 32;
	else
		ei->i_dir_acl = le32_to_cpu(raw_inode->i_dir_acl);
	ei->i_dtime = 0;
	inode->i_generation = le32_to_cpu(raw_inode->i_generation);
	ei->i_state = 0;
	ei->i_next_alloc_block = 0;
	ei->i_next_alloc_goal = 0;
	ei->i_prealloc_count = 0;
	ei->i_block_group = (ino - 1) / EXT2_INODES_PER_GROUP(inode->i_sb);
	ei->i_dir_start_lookup = 0;

	/*
	 * NOTE! The in-memory inode i_data array is in little-endian order
	 * even on big-endian machines: we do NOT byteswap the block numbers!
	 */
	for (n = 0; n < EXT2_N_BLOCKS; n++)
		ei->i_data[n] = raw_inode->i_block[n];

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &ext2_file_inode_operations;
		inode->i_fop = &ext2_file_operations;
		if (test_opt(inode->i_sb, NOBH))
			inode->i_mapping->a_ops = &ext2_nobh_aops;
		else
			inode->i_mapping->a_ops = &ext2_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &ext2_dir_inode_operations;
		inode->i_fop = &ext2_dir_operations;
		if (test_opt(inode->i_sb, NOBH))
			inode->i_mapping->a_ops = &ext2_nobh_aops;
		else
			inode->i_mapping->a_ops = &ext2_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		if (ext2_inode_is_fast_symlink(inode))
			inode->i_op = &ext2_fast_symlink_inode_operations;
		else {
			inode->i_op = &ext2_symlink_inode_operations;
			if (test_opt(inode->i_sb, NOBH))
				inode->i_mapping->a_ops = &ext2_nobh_aops;
			else
				inode->i_mapping->a_ops = &ext2_aops;
		}
	} else {
		inode->i_op = &ext2_special_inode_operations;
		if (raw_inode->i_block[0])
			init_special_inode(inode, inode->i_mode,
			   old_decode_dev(le32_to_cpu(raw_inode->i_block[0])));
		else 
			init_special_inode(inode, inode->i_mode,
			   new_decode_dev(le32_to_cpu(raw_inode->i_block[1])));
	}
	brelse (bh);
	ext2_set_inode_flags(inode);
	return;
	
bad_inode:
	make_bad_inode(inode);
	return;
}

static int ext2_update_inode(struct inode * inode, int do_sync)
{
    panic("in ext2_update_inode");
    return 0;
}

int ext2_write_inode(struct inode *inode, int wait)
{
	return ext2_update_inode(inode, wait);
}

int ext2_sync_inode(struct inode *inode)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = 0,	/* sys_fsync did this */
	};
	return sync_inode(inode, &wbc);
}

int ext2_setattr(struct dentry *dentry, struct iattr *iattr)
{
    panic("in ext2_setattr");
    return 0;
}

