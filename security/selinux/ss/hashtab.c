#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include "hashtab.h"

void *hashtab_search(struct hashtab *h, void *key)
{
	u32 hvalue;
	struct hashtab_node *cur;

	if (!h)
		return NULL;

	hvalue = h->hash_value(h, key);
	cur = h->htable[hvalue];
	while (cur != NULL && h->keycmp(h, key, cur->key) > 0)
		cur = cur->next;

	if (cur == NULL || (h->keycmp(h, key, cur->key) != 0))
		return NULL;

	return cur->datum;
}