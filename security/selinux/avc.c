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

static struct avc_cache avc_cache;
static struct avc_callback_node *avc_callbacks;
static kmem_cache_t *avc_node_cachep;

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