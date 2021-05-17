#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <net/sock.h>
#include <linux/un.h>
#include <net/af_unix.h>
#include <linux/ip.h>
#include <linux/audit.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include "avc.h"
#include "avc_ss.h"

#define AVC_CACHE_SLOTS			512
#define AVC_DEF_CACHE_THRESHOLD		512
#define AVC_CACHE_RECLAIM		16

#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
#define avc_cache_stats_incr(field) 				\
do {								\
	per_cpu(avc_cache_stats, get_cpu()).field++;		\
	put_cpu();						\
} while (0)
#else
#define avc_cache_stats_incr(field)	do {} while (0)
#endif

struct avc_entry {
	u32			ssid;
	u32			tsid;
	u16			tclass;
	struct av_decision	avd;
	atomic_t		used;	/* used recently */
};

struct avc_node {
	struct avc_entry	ae;
	struct list_head	list;
	struct rcu_head         rhead;
};

struct avc_cache {
	struct list_head	slots[AVC_CACHE_SLOTS];
	spinlock_t		slots_lock[AVC_CACHE_SLOTS]; /* lock for writes */
	atomic_t		lru_hint;	/* LRU hint for reclaim scan */
	atomic_t		active_nodes;
	u32			latest_notif;	/* latest revocation notification */
};

struct avc_callback_node {
	int (*callback) (u32 event, u32 ssid, u32 tsid,
	                 u16 tclass, u32 perms,
	                 u32 *out_retained);
	u32 events;
	u32 ssid;
	u32 tsid;
	u16 tclass;
	u32 perms;
	struct avc_callback_node *next;
};

/* Exported via selinufs */
unsigned int avc_cache_threshold = AVC_DEF_CACHE_THRESHOLD;

#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
DEFINE_PER_CPU(struct avc_cache_stats, avc_cache_stats) = { 0 };
#endif

static struct avc_cache avc_cache;
static struct avc_callback_node *avc_callbacks;
static kmem_cache_t *avc_node_cachep;

static inline int avc_hash(u32 ssid, u32 tsid, u16 tclass)
{
	return (ssid ^ (tsid<<2) ^ (tclass<<4)) & (AVC_CACHE_SLOTS - 1);
}

void __init avc_init(void)
{
    int i;

	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		INIT_LIST_HEAD(&avc_cache.slots[i]);
		spin_lock_init(&avc_cache.slots_lock[i]);
	}
	atomic_set(&avc_cache.active_nodes, 0);
	atomic_set(&avc_cache.lru_hint, 0);

	avc_node_cachep = kmem_cache_create("avc_node", sizeof(struct avc_node),
					     0, SLAB_PANIC, NULL, NULL);

	audit_log(current->audit_context, "AVC INITIALIZED\n");
}

static void avc_node_free(struct rcu_head *rhead)
{
	struct avc_node *node = container_of(rhead, struct avc_node, rhead);
	kmem_cache_free(avc_node_cachep, node);
	avc_cache_stats_incr(frees);
}

static void avc_node_delete(struct avc_node *node)
{
	list_del_rcu(&node->list);
	call_rcu(&node->rhead, avc_node_free);
	atomic_dec(&avc_cache.active_nodes);
}

static void avc_node_kill(struct avc_node *node)
{
	kmem_cache_free(avc_node_cachep, node);
	avc_cache_stats_incr(frees);
	atomic_dec(&avc_cache.active_nodes);
}

static void avc_node_replace(struct avc_node *new, struct avc_node *old)
{
	list_replace_rcu(&old->list, &new->list);
	call_rcu(&old->rhead, avc_node_free);
	atomic_dec(&avc_cache.active_nodes);
}

static inline int avc_reclaim_node(void)
{
	struct avc_node *node;
	int hvalue, try, ecx;
	unsigned long flags;

	for (try = 0, ecx = 0; try < AVC_CACHE_SLOTS; try++ ) {
		hvalue = atomic_inc_return(&avc_cache.lru_hint) & (AVC_CACHE_SLOTS - 1);

		if (!spin_trylock_irqsave(&avc_cache.slots_lock[hvalue], flags))
			continue;

		list_for_each_entry(node, &avc_cache.slots[hvalue], list) {
			if (atomic_dec_and_test(&node->ae.used)) {
				/* Recently Unused */
				avc_node_delete(node);
				avc_cache_stats_incr(reclaims);
				ecx++;
				if (ecx >= AVC_CACHE_RECLAIM) {
					spin_unlock_irqrestore(&avc_cache.slots_lock[hvalue], flags);
					goto out;
				}
			}
		}
		spin_unlock_irqrestore(&avc_cache.slots_lock[hvalue], flags);
	}
out:
	return ecx;
}

static struct avc_node *avc_alloc_node(void)
{
	struct avc_node *node;

	node = kmem_cache_alloc(avc_node_cachep, SLAB_ATOMIC);
	if (!node)
		goto out;

	memset(node, 0, sizeof(*node));
	INIT_RCU_HEAD(&node->rhead);
	INIT_LIST_HEAD(&node->list);
	atomic_set(&node->ae.used, 1);
	avc_cache_stats_incr(allocations);

	if (atomic_inc_return(&avc_cache.active_nodes) > avc_cache_threshold)
		avc_reclaim_node();

out:
	return node;
}

static void avc_node_populate(struct avc_node *node, u32 ssid, u32 tsid, u16 tclass, struct avc_entry *ae)
{
	node->ae.ssid = ssid;
	node->ae.tsid = tsid;
	node->ae.tclass = tclass;
	memcpy(&node->ae.avd, &ae->avd, sizeof(node->ae.avd));
}

static inline struct avc_node *avc_search_node(u32 ssid, u32 tsid, u16 tclass)
{
	struct avc_node *node, *ret = NULL;
	int hvalue;

	hvalue = avc_hash(ssid, tsid, tclass);
	list_for_each_entry_rcu(node, &avc_cache.slots[hvalue], list) {
		if (ssid == node->ae.ssid &&
		    tclass == node->ae.tclass &&
		    tsid == node->ae.tsid) {
			ret = node;
			break;
		}
	}

	if (ret == NULL) {
		/* cache miss */
		goto out;
	}

	/* cache hit */
	if (atomic_read(&ret->ae.used) != 1)
		atomic_set(&ret->ae.used, 1);
out:
	return ret;
}

static struct avc_node *avc_lookup(u32 ssid, u32 tsid, u16 tclass, u32 requested)
{
	struct avc_node *node;

	avc_cache_stats_incr(lookups);
	node = avc_search_node(ssid, tsid, tclass);

	if (node && ((node->ae.avd.decided & requested) == requested)) {
		avc_cache_stats_incr(hits);
		goto out;
	}

	node = NULL;
	avc_cache_stats_incr(misses);
out:
	return node;
}

static int avc_latest_notif_update(int seqno, int is_insert)
{
	int ret = 0;
	static DEFINE_SPINLOCK(notif_lock);
	unsigned long flag;

	spin_lock_irqsave(&notif_lock, flag);
	if (is_insert) {
		if (seqno < avc_cache.latest_notif) {
			printk(KERN_WARNING "avc:  seqno %d < latest_notif %d\n",
			       seqno, avc_cache.latest_notif);
			ret = -EAGAIN;
		}
	} else {
		if (seqno > avc_cache.latest_notif)
			avc_cache.latest_notif = seqno;
	}
	spin_unlock_irqrestore(&notif_lock, flag);

	return ret;
}

static struct avc_node *avc_insert(u32 ssid, u32 tsid, u16 tclass, struct avc_entry *ae)
{
	struct avc_node *pos, *node = NULL;
	int hvalue;
	unsigned long flag;

	if (avc_latest_notif_update(ae->avd.seqno, 1))
		goto out;

	node = avc_alloc_node();
	if (node) {
		hvalue = avc_hash(ssid, tsid, tclass);
		avc_node_populate(node, ssid, tsid, tclass, ae);

		spin_lock_irqsave(&avc_cache.slots_lock[hvalue], flag);
		list_for_each_entry(pos, &avc_cache.slots[hvalue], list) {
			if (pos->ae.ssid == ssid &&
			    pos->ae.tsid == tsid &&
			    pos->ae.tclass == tclass) {
			    	avc_node_replace(node, pos);
				goto found;
			}
		}
		list_add_rcu(&node->list, &avc_cache.slots[hvalue]);
found:
		spin_unlock_irqrestore(&avc_cache.slots_lock[hvalue], flag);
	}
out:
	return node;
}

void avc_audit(u32 ssid, u32 tsid,
               u16 tclass, u32 requested,
               struct av_decision *avd, int result, struct avc_audit_data *a)
{
	printk("######## avc_audit not implement");
}

static int avc_update_node(u32 event, u32 perms, u32 ssid, u32 tsid, u16 tclass)
{
	int hvalue, rc = 0;
	unsigned long flag;
	struct avc_node *pos, *node, *orig = NULL;

	node = avc_alloc_node();
	if (!node) {
		rc = -ENOMEM;
		goto out;
	}

	/* Lock the target slot */
	hvalue = avc_hash(ssid, tsid, tclass);
	spin_lock_irqsave(&avc_cache.slots_lock[hvalue], flag);

	list_for_each_entry(pos, &avc_cache.slots[hvalue], list){
		if ( ssid==pos->ae.ssid &&
		     tsid==pos->ae.tsid &&
		     tclass==pos->ae.tclass ){
			orig = pos;
			break;
		}
	}

	if (!orig) {
		rc = -ENOENT;
		avc_node_kill(node);
		goto out_unlock;
	}

	/*
	 * Copy and replace original node.
	 */

	avc_node_populate(node, ssid, tsid, tclass, &orig->ae);

	switch (event) {
	case AVC_CALLBACK_GRANT:
		node->ae.avd.allowed |= perms;
		break;
	case AVC_CALLBACK_TRY_REVOKE:
	case AVC_CALLBACK_REVOKE:
		node->ae.avd.allowed &= ~perms;
		break;
	case AVC_CALLBACK_AUDITALLOW_ENABLE:
		node->ae.avd.auditallow |= perms;
		break;
	case AVC_CALLBACK_AUDITALLOW_DISABLE:
		node->ae.avd.auditallow &= ~perms;
		break;
	case AVC_CALLBACK_AUDITDENY_ENABLE:
		node->ae.avd.auditdeny |= perms;
		break;
	case AVC_CALLBACK_AUDITDENY_DISABLE:
		node->ae.avd.auditdeny &= ~perms;
		break;
	}
	avc_node_replace(node, orig);
out_unlock:
	spin_unlock_irqrestore(&avc_cache.slots_lock[hvalue], flag);
out:
	return rc;
}

int avc_has_perm_noaudit(u32 ssid, u32 tsid,
                         u16 tclass, u32 requested,
                         struct av_decision *avd)
{
	struct avc_node *node;
	struct avc_entry entry, *p_ae;
	int rc = 0;
	u32 denied;

	rcu_read_lock();

	node = avc_lookup(ssid, tsid, tclass, requested);
	if (!node) {
		rcu_read_unlock();
		rc = security_compute_av(ssid,tsid,tclass,requested,&entry.avd);
		if (rc)
			goto out;
		rcu_read_lock();
		node = avc_insert(ssid,tsid,tclass,&entry);
	}

	p_ae = node ? &node->ae : &entry;

	if (avd)
		memcpy(avd, &p_ae->avd, sizeof(*avd));

	denied = requested & ~(p_ae->avd.allowed);

	if (!requested || denied) {
		if (selinux_enforcing)
			rc = -EACCES;
		else
			if (node)
				avc_update_node(AVC_CALLBACK_GRANT,requested,
						ssid,tsid,tclass);
	}

	rcu_read_unlock();
out:
	return rc;
}

int avc_has_perm(u32 ssid, u32 tsid, u16 tclass,
                 u32 requested, struct avc_audit_data *auditdata)
{
	struct av_decision avd;
	int rc;

	rc = avc_has_perm_noaudit(ssid, tsid, tclass, requested, &avd);
	avc_audit(ssid, tsid, tclass, requested, &avd, rc, auditdata);
	return rc;
}