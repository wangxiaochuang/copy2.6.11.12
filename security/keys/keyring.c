#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/err.h>
#include <asm/uaccess.h>
#include "internal.h"

#define KEYRING_SEARCH_MAX_DEPTH 6

/*
 * we keep all named keyrings in a hash to speed looking them up
 */
#define KEYRING_NAME_HASH_SIZE	(1 << 5)

static struct list_head	keyring_name_hash[KEYRING_NAME_HASH_SIZE];
static DEFINE_RWLOCK(keyring_name_lock);

static inline unsigned keyring_hash(const char *desc)
{
	unsigned bucket = 0;

	for (; *desc; desc++)
		bucket += (unsigned char) *desc;

	return bucket & (KEYRING_NAME_HASH_SIZE - 1);
}

static int keyring_instantiate(struct key *keyring,
			       const void *data, size_t datalen);
static int keyring_duplicate(struct key *keyring, const struct key *source);
static int keyring_match(const struct key *keyring, const void *criterion);
static void keyring_destroy(struct key *keyring);
static void keyring_describe(const struct key *keyring, struct seq_file *m);
static long keyring_read(const struct key *keyring,
			 char __user *buffer, size_t buflen);

struct key_type key_type_keyring = {
	.name		= "keyring",
	.def_datalen	= sizeof(struct keyring_list),
	.instantiate	= keyring_instantiate,
	.duplicate	= keyring_duplicate,
	.match		= keyring_match,
	.destroy	= keyring_destroy,
	.describe	= keyring_describe,
	.read		= keyring_read,
};

DECLARE_RWSEM(keyring_serialise_link_sem);

void keyring_publish_name(struct key *keyring)
{
	int bucket;

	if (keyring->description) {
		bucket = keyring_hash(keyring->description);

		write_lock(&keyring_name_lock);

		if (!keyring_name_hash[bucket].next)
			INIT_LIST_HEAD(&keyring_name_hash[bucket]);

		list_add_tail(&keyring->type_data.link,
			      &keyring_name_hash[bucket]);

		write_unlock(&keyring_name_lock);
	}

}

static int keyring_instantiate(struct key *keyring,
			       const void *data, size_t datalen) {
                       return 0;
                   }

static int keyring_duplicate(struct key *keyring, const struct key *source) {
    return 0;
}

static int keyring_match(const struct key *keyring, const void *description) {
    return 0;
}

static void keyring_destroy(struct key *keyring) {
}

static void keyring_describe(const struct key *keyring, struct seq_file *m) {

}

static long keyring_read(const struct key *keyring,
			 char __user *buffer, size_t buflen) {
                 return 0;
             }

static int keyring_detect_cycle(struct key *A, struct key *B)
{
	struct {
		struct key *subtree;
		int kix;
	} stack[KEYRING_SEARCH_MAX_DEPTH];

	struct keyring_list *keylist;
	struct key *subtree, *key;
	int sp, kix, ret;

	ret = -EDEADLK;
	if (A == B)
		goto error;

	subtree = B;
	sp = 0;

	/* start processing a new keyring */
 descend:
	read_lock(&subtree->lock);
	if (subtree->flags & KEY_FLAG_REVOKED)
		goto not_this_keyring;

	keylist = subtree->payload.subscriptions;
	if (!keylist)
		goto not_this_keyring;
	kix = 0;

 ascend:
	/* iterate through the remaining keys in this keyring */
	for (; kix < keylist->nkeys; kix++) {
		key = keylist->keys[kix];

		if (key == A)
			goto cycle_detected;

		/* recursively check nested keyrings */
		if (key->type == &key_type_keyring) {
			if (sp >= KEYRING_SEARCH_MAX_DEPTH)
				goto too_deep;

			/* stack the current position */
			stack[sp].subtree = subtree;
			stack[sp].kix = kix;
			sp++;

			/* begin again with the new keyring */
			subtree = key;
			goto descend;
		}
	}

	/* the keyring we're looking at was disqualified or didn't contain a
	 * matching key */
 not_this_keyring:
	read_unlock(&subtree->lock);

	if (sp > 0) {
		/* resume the checking of a keyring higher up in the tree */
		sp--;
		subtree = stack[sp].subtree;
		keylist = subtree->payload.subscriptions;
		kix = stack[sp].kix + 1;
		goto ascend;
	}

	ret = 0; /* no cycles detected */

 error:
	return ret;

 too_deep:
	ret = -ELOOP;
	goto error_unwind;
 cycle_detected:
	ret = -EDEADLK;
 error_unwind:
	read_unlock(&subtree->lock);

	/* unwind the keyring stack */
	while (sp > 0) {
		sp--;
		read_unlock(&stack[sp].subtree->lock);
	}

	goto error;

} /* end keyring_detect_cycle() */

int __key_link(struct key *keyring, struct key *key)
{
	struct keyring_list *klist, *nklist;
	unsigned max;
	size_t size;
	int ret;

	ret = -EKEYREVOKED;
	if (keyring->flags & KEY_FLAG_REVOKED)
		goto error;

	ret = -ENOTDIR;
	if (keyring->type != &key_type_keyring)
		goto error;

	down_write(&keyring_serialise_link_sem);

	/* check that we aren't going to create a cycle adding one keyring to
	 * another */
	if (key->type == &key_type_keyring) {
		ret = keyring_detect_cycle(keyring, key);
		if (ret < 0)
			goto error2;
	}

	/* check that we aren't going to overrun the user's quota */
	ret = key_payload_reserve(keyring,
				  keyring->datalen + KEYQUOTA_LINK_BYTES);
	if (ret < 0)
		goto error2;

	klist = keyring->payload.subscriptions;

	if (klist && klist->nkeys < klist->maxkeys) {
		/* there's sufficient slack space to add directly */
		atomic_inc(&key->usage);

		write_lock(&keyring->lock);
		klist->keys[klist->nkeys++] = key;
		write_unlock(&keyring->lock);

		ret = 0;
	} else {
		/* grow the key list */
		max = 4;
		if (klist)
			max += klist->maxkeys;

		ret = -ENFILE;
		size = sizeof(*klist) + sizeof(*key) * max;
		if (size > PAGE_SIZE)
			goto error3;

		ret = -ENOMEM;
		nklist = kmalloc(size, GFP_KERNEL);
		if (!nklist)
			goto error3;
		nklist->maxkeys = max;
		nklist->nkeys = 0;

		if (klist) {
			nklist->nkeys = klist->nkeys;
			memcpy(nklist->keys,
			       klist->keys,
			       sizeof(struct key *) * klist->nkeys);
		}

		/* add the key into the new space */
		atomic_inc(&key->usage);

		write_lock(&keyring->lock);
		keyring->payload.subscriptions = nklist;
		nklist->keys[nklist->nkeys++] = key;
		write_unlock(&keyring->lock);

		/* dispose of the old keyring list */
		kfree(klist);

		ret = 0;
	}

 error2:
	up_write(&keyring_serialise_link_sem);
 error:
	return ret;

 error3:
	/* undo the quota changes */
	key_payload_reserve(keyring,
			    keyring->datalen - KEYQUOTA_LINK_BYTES);
	goto error2;
}

int key_link(struct key *keyring, struct key *key)
{
	int ret;

	key_check(keyring);
	key_check(key);

	down_write(&keyring->sem);
	ret = __key_link(keyring, key);
	up_write(&keyring->sem);

	return ret;

} /* end key_link() */

EXPORT_SYMBOL(key_link);