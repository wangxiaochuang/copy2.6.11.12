#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>

#include "avtab.h"
#include "policydb.h"

#define AVTAB_HASH(keyp) \
((keyp->target_class + \
 (keyp->target_type << 2) + \
 (keyp->source_type << 9)) & \
 AVTAB_HASH_MASK)

static kmem_cache_t *avtab_node_cachep;

struct avtab_datum *avtab_search(struct avtab *h, struct avtab_key *key, int specified)
{
    int hvalue;
	struct avtab_node *cur;

	if (!h)
		return NULL;

	hvalue = AVTAB_HASH(key);
	for (cur = h->htable[hvalue]; cur; cur = cur->next) {
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->datum.specified))
			return &cur->datum;

		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}

	return NULL;
}

struct avtab_node*
avtab_search_node(struct avtab *h, struct avtab_key *key, int specified)
{
	int hvalue;
	struct avtab_node *cur;

	if (!h)
		return NULL;

	hvalue = AVTAB_HASH(key);
	for (cur = h->htable[hvalue]; cur; cur = cur->next) {
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->datum.specified))
			return cur;

		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}
	return NULL;
}

struct avtab_node*
avtab_search_node_next(struct avtab_node *node, int specified)
{
	struct avtab_node *cur;

	if (!node)
		return NULL;

	for (cur = node->next; cur; cur = cur->next) {
		if (node->key.source_type == cur->key.source_type &&
		    node->key.target_type == cur->key.target_type &&
		    node->key.target_class == cur->key.target_class &&
		    (specified & cur->datum.specified))
			return cur;

		if (node->key.source_type < cur->key.source_type)
			break;
		if (node->key.source_type == cur->key.source_type &&
		    node->key.target_type < cur->key.target_type)
			break;
		if (node->key.source_type == cur->key.source_type &&
		    node->key.target_type == cur->key.target_type &&
		    node->key.target_class < cur->key.target_class)
			break;
	}
	return NULL;
}