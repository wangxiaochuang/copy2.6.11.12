#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/radix-tree.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/bitops.h>

#ifdef __KERNEL__
#define RADIX_TREE_MAP_SHIFT	6
#else
#define RADIX_TREE_MAP_SHIFT	3	/* For more stressful testing */
#endif
#define RADIX_TREE_TAGS		2

#define RADIX_TREE_MAP_SIZE	(1UL << RADIX_TREE_MAP_SHIFT)

#define RADIX_TREE_TAG_LONGS	\
	((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) / BITS_PER_LONG)

struct radix_tree_node {
	unsigned int	count;
	void		*slots[RADIX_TREE_MAP_SIZE];
	unsigned long	tags[RADIX_TREE_TAGS][RADIX_TREE_TAG_LONGS];
};

struct radix_tree_path {
	struct radix_tree_node *node, **slot;
	int offset;
};

#define RADIX_TREE_INDEX_BITS  (8 /* CHAR_BIT */ * sizeof(unsigned long))
#define RADIX_TREE_MAX_PATH (RADIX_TREE_INDEX_BITS/RADIX_TREE_MAP_SHIFT + 2)

static unsigned long height_to_maxindex[RADIX_TREE_MAX_PATH];

/*
 * Radix tree node cache.
 */
static kmem_cache_t *radix_tree_node_cachep;

unsigned int
radix_tree_gang_lookup_tag(struct radix_tree_root *root, void **results,
		unsigned long first_index, unsigned int max_items, int tag)
{
    return 0;
}

static void
radix_tree_node_ctor(void *node, kmem_cache_t *cachep, unsigned long flags)
{
	memset(node, 0, sizeof(struct radix_tree_node));
}

static __init unsigned long __maxindex(unsigned int height)
{
	unsigned int tmp = height * RADIX_TREE_MAP_SHIFT;
	unsigned long index = (~0UL >> (RADIX_TREE_INDEX_BITS - tmp - 1)) >> 1;

	if (tmp >= RADIX_TREE_INDEX_BITS)
		index = ~0UL;
	return index;
}

static __init void radix_tree_init_maxindex(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(height_to_maxindex); i++)
		height_to_maxindex[i] = __maxindex(i);
}

void __init radix_tree_init(void)
{
	radix_tree_node_cachep = kmem_cache_create("radix_tree_node",
			sizeof(struct radix_tree_node), 0,
			SLAB_PANIC, radix_tree_node_ctor, NULL);
	radix_tree_init_maxindex();
	hotcpu_notifier(radix_tree_callback, 0);
}