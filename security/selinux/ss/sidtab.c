#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include "flask.h"
#include "security.h"
#include "sidtab.h"

#define SIDTAB_HASH(sid) \
(sid & SIDTAB_HASH_MASK)

#define INIT_SIDTAB_LOCK(s) spin_lock_init(&s->lock)
#define SIDTAB_LOCK(s, x) spin_lock_irqsave(&s->lock, x)
#define SIDTAB_UNLOCK(s, x) spin_unlock_irqrestore(&s->lock, x)

int sidtab_insert(struct sidtab *s, u32 sid, struct context *context)
{
	int hvalue, rc = 0;
	struct sidtab_node *prev, *cur, *newnode;

	if (!s) {
		rc = -ENOMEM;
		goto out;
	}

	hvalue = SIDTAB_HASH(sid);
	prev = NULL;
	cur = s->htable[hvalue];
	while (cur != NULL && sid > cur->sid) {
		prev = cur;
		cur = cur->next;
	}

	if (cur && sid == cur->sid) {
		rc = -EEXIST;
		goto out;
	}

	newnode = kmalloc(sizeof(*newnode), GFP_ATOMIC);
	if (newnode == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	newnode->sid = sid;
	if (context_cpy(&newnode->context, context)) {
		kfree(newnode);
		rc = -ENOMEM;
		goto out;
	}

	if (prev) {
		newnode->next = prev->next;
		wmb();
		prev->next = newnode;
	} else {
		newnode->next = s->htable[hvalue];
		wmb();
		s->htable[hvalue] = newnode;
	}

	s->nel++;
	if (sid >= s->next_sid)
		s->next_sid = sid + 1;
out:
	return rc;
}

struct context *sidtab_search(struct sidtab *s, u32 sid)
{
	int hvalue;
	struct sidtab_node *cur;

	if (!s)
		return NULL;

	hvalue = SIDTAB_HASH(sid);
	cur = s->htable[hvalue];
	while (cur != NULL && sid > cur->sid)
		cur = cur->next;

	if (cur == NULL || sid != cur->sid) {
		/* Remap invalid SIDs to the unlabeled SID. */
		sid = SECINITSID_UNLABELED;
		hvalue = SIDTAB_HASH(sid);
		cur = s->htable[hvalue];
		while (cur != NULL && sid > cur->sid)
			cur = cur->next;
		if (!cur || sid != cur->sid)
			return NULL;
	}

	return &cur->context;
}

static inline u32 sidtab_search_context(struct sidtab *s,
						  struct context *context)
{
	int i;
	struct sidtab_node *cur;

	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = s->htable[i];
		while (cur != NULL) {
			if (context_cmp(&cur->context, context))
				return cur->sid;
			cur = cur->next;
		}
	}
	return 0;
}

int sidtab_context_to_sid(struct sidtab *s,
			  struct context *context,
			  u32 *out_sid)
{
	u32 sid;
	int ret = 0;
	unsigned long flags;

	*out_sid = SECSID_NULL;

	sid = sidtab_search_context(s, context);
	if (!sid) {
		SIDTAB_LOCK(s, flags);
		/* Rescan now that we hold the lock. */
		sid = sidtab_search_context(s, context);
		if (sid)
			goto unlock_out;
		/* No SID exists for the context.  Allocate a new one. */
		if (s->next_sid == UINT_MAX || s->shutdown) {
			ret = -ENOMEM;
			goto unlock_out;
		}
		sid = s->next_sid++;
		ret = sidtab_insert(s, sid, context);
		if (ret)
			s->next_sid--;
unlock_out:
		SIDTAB_UNLOCK(s, flags);
	}

	if (ret)
		return ret;

	*out_sid = sid;
	return 0;
}