#include <linux/config.h>
#include "ext2.h"
#include <linux/quotaops.h>
#include <linux/sched.h>
#include <linux/buffer_head.h>

#define in_range(b, first, len)	((b) >= (first) && (b) <= (first) + (len) - 1)

struct ext2_group_desc * ext2_get_group_desc(struct super_block * sb,
					     unsigned int block_group,
					     struct buffer_head ** bh)
{
    panic("in ext2_get_group_desc");
	return NULL;
}

static struct buffer_head *
read_block_bitmap(struct super_block *sb, unsigned int block_group)
{
    panic("in read_block_bitmap");
	return NULL;
}

static int reserve_blocks(struct super_block *sb, int count)
{
    panic("in reserve_blocks");
	return 0;
}

static void release_blocks(struct super_block *sb, int count)
{
    panic("in release_blocks");
}

static int group_reserve_blocks(struct ext2_sb_info *sbi, int group_no,
	struct ext2_group_desc *desc, struct buffer_head *bh, int count)
{
    panic("in group_reserve_blocks");
	return 0;
}

static void group_release_blocks(struct super_block *sb, int group_no,
	struct ext2_group_desc *desc, struct buffer_head *bh, int count)
{
    panic("in group_release_blocks");
}

void ext2_free_blocks (struct inode * inode, unsigned long block,
		       unsigned long count)
{
    panic("in ext2_free_blocks");
}

static int grab_block(spinlock_t *lock, char *map, unsigned size, int goal)
{
    panic("in grab_block");
	return 0;
}

int ext2_new_block(struct inode *inode, unsigned long goal,
			u32 *prealloc_count, u32 *prealloc_block, int *err)
{
    panic("in ext2_new_block");
	return 0;
}

unsigned long ext2_count_free_blocks (struct super_block * sb)
{
    panic("in ext2_count_free_blocks");
	return 0;
}

static inline int
block_in_use(unsigned long block, struct super_block *sb, unsigned char *map)
{
    panic("in block_in_use");
	return 0;
}

static inline int test_root(int a, int b)
{
	int num = b;

	while (a > num)
		num *= b;
	return num == a;
}

static int ext2_group_sparse(int group)
{
	if (group <= 1)
		return 1;
	return (test_root(group, 3) || test_root(group, 5) ||
		test_root(group, 7));
}

int ext2_bg_has_super(struct super_block *sb, int group)
{
	if (EXT2_HAS_RO_COMPAT_FEATURE(sb,EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER)&&
	    !ext2_group_sparse(group))
		return 0;
	return 1;
}

unsigned long ext2_bg_num_gdb(struct super_block *sb, int group)
{
	if (EXT2_HAS_RO_COMPAT_FEATURE(sb,EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER)&&
	    !ext2_group_sparse(group))
		return 0;
	return EXT2_SB(sb)->s_gdb_count;
}

#ifdef CONFIG_EXT2_CHECK
#error "CONFIG_EXT2_CHECK"
#endif

