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
	unsigned long group_desc;
	unsigned long offset;
	struct ext2_group_desc * desc;
	struct ext2_sb_info *sbi = EXT2_SB(sb);

	if (block_group >= sbi->s_groups_count) {
		ext2_error (sb, "ext2_get_group_desc",
			    "block_group >= groups_count - "
			    "block_group = %d, groups_count = %lu",
			    block_group, sbi->s_groups_count);

		return NULL;
	}

	group_desc = block_group >> EXT2_DESC_PER_BLOCK_BITS(sb);
	offset = block_group & (EXT2_DESC_PER_BLOCK(sb) - 1);
	if (!sbi->s_group_desc[group_desc]) {
		ext2_error (sb, "ext2_get_group_desc",
			    "Group descriptor not loaded - "
			    "block_group = %d, group_desc = %lu, desc = %lu",
			     block_group, group_desc, offset);
		return NULL;
	}

	desc = (struct ext2_group_desc *) sbi->s_group_desc[group_desc]->b_data;
	if (bh)
		*bh = sbi->s_group_desc[group_desc];
	return desc + offset;
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
	struct ext2_group_desc * desc;
	unsigned long desc_count = 0;
	int i;

	for (i = 0; i < EXT2_SB(sb)->s_groups_count; i++) {
                desc = ext2_get_group_desc (sb, i, NULL);
                if (!desc)
                        continue;
                desc_count += le16_to_cpu(desc->bg_free_blocks_count);
	}
	return desc_count;
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

