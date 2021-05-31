#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/err.h>
#include "internal.h"

static kmem_cache_t	*key_jar;
static key_serial_t	key_serial_next = 3;
struct rb_root		key_serial_tree; /* tree of keys indexed by serial */
DEFINE_SPINLOCK(key_serial_lock);

struct rb_root	key_user_tree; /* tree of quota records indexed by UID */
DEFINE_SPINLOCK(key_user_lock);

static LIST_HEAD(key_types_list);
static DECLARE_RWSEM(key_types_sem);

static void key_cleanup(void *data);
static DECLARE_WORK(key_cleanup_task, key_cleanup, NULL);

/* we serialise key instantiation and link */
DECLARE_RWSEM(key_construction_sem);

/* any key who's type gets unegistered will be re-typed to this */
struct key_type key_type_dead = {
	.name		= "dead",
};

struct key_user *key_user_lookup(uid_t uid)
{
	return NULL;
}

void key_user_put(struct key_user *user)
{
}

static void __init __key_insert_serial(struct key *key)
{
	struct rb_node *parent, **p;
	struct key *xkey;

	parent = NULL;
	p = &key_serial_tree.rb_node;

	while (*p) {
		parent = *p;
		xkey = rb_entry(parent, struct key, serial_node);

		if (key->serial < xkey->serial)
			p = &(*p)->rb_left;
		else if (key->serial > xkey->serial)
			p = &(*p)->rb_right;
		else
			BUG();
	}

	/* we've found a suitable hole - arrange for this key to occupy it */
	rb_link_node(&key->serial_node, parent, p);
	rb_insert_color(&key->serial_node, &key_serial_tree);
}

static inline void key_alloc_serial(struct key *key)
{
}

struct key *key_alloc(struct key_type *type, const char *desc,
		      uid_t uid, gid_t gid, key_perm_t perm,
		      int not_in_quota)
{
	return NULL;
}

int key_payload_reserve(struct key *key, size_t datalen)
{
	int delta = (int) datalen - key->datalen;
	int ret = 0;

	key_check(key);

	/* contemplate the quota adjustment */
	if (delta != 0 && key->flags & KEY_FLAG_IN_QUOTA) {
		spin_lock(&key->user->lock);

		if (delta > 0 &&
		    key->user->qnbytes + delta > KEYQUOTA_MAX_BYTES
		    ) {
			ret = -EDQUOT;
		}
		else {
			key->user->qnbytes += delta;
			key->quotalen += delta;
		}
		spin_unlock(&key->user->lock);
	}

	/* change the recorded data length if that didn't generate an error */
	if (ret == 0)
		key->datalen = datalen;

	return ret;

} /* end key_payload_reserve() */

EXPORT_SYMBOL(key_payload_reserve);


/*****************************************************************************/
/*
 * do cleaning up in process context so that we don't have to disable
 * interrupts all over the place
 */
static void key_cleanup(void *data)
{
	panic("in key_cleanup function");
}

/*****************************************************************************/
/*
 * dispose of a reference to a key
 * - when all the references are gone, we schedule the cleanup task to come and
 *   pull it out of the tree in definite process context
 */
void key_put(struct key *key)
{
	if (key) {
		key_check(key);

		if (atomic_dec_and_test(&key->usage))
			schedule_work(&key_cleanup_task);
	}

} /* end key_put() */

EXPORT_SYMBOL(key_put);

/*****************************************************************************/
/*
 * initialise the key management stuff
 */
void __init key_init(void)
{
	/* allocate a slab in which we can store keys */
	key_jar = kmem_cache_create("key_jar", sizeof(struct key),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);

	/* add the special key types */
	list_add_tail(&key_type_keyring.link, &key_types_list);
	list_add_tail(&key_type_dead.link, &key_types_list);
	list_add_tail(&key_type_user.link, &key_types_list);

	/* record the root user tracking */
	rb_link_node(&root_key_user.node,
		     NULL,
		     &key_user_tree.rb_node);

	rb_insert_color(&root_key_user.node,
			&key_user_tree);

	/* record root's user standard keyrings */
	key_check(&root_user_keyring);
	key_check(&root_session_keyring);

	__key_insert_serial(&root_user_keyring);
	__key_insert_serial(&root_session_keyring);

	keyring_publish_name(&root_user_keyring);
	keyring_publish_name(&root_session_keyring);

	/* link the two root keyrings together */
	key_link(&root_session_keyring, &root_user_keyring);
}