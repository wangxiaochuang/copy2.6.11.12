#include <linux/config.h>
#include <linux/mm.h>
#include <linux/smp_lock.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/wanrouter.h>
#include <linux/if_bridge.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/divert.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/kmod.h>

#ifdef CONFIG_NET_RADIO
#include <linux/wireless.h>		/* Note : will define WIRELESS_EXT */
#endif	/* CONFIG_NET_RADIO */

#include <asm/uaccess.h>
#include <asm/unistd.h>

#include <net/compat.h>

#include <net/sock.h>
#include <linux/netfilter.h>


#define SOCKFS_MAGIC 0x534F434B

static kmem_cache_t * sock_inode_cachep;

static void sock_destroy_inode(struct inode *inode)
{
	kmem_cache_free(sock_inode_cachep,
			container_of(inode, struct socket_alloc, vfs_inode));
}

static void init_once(void * foo, kmem_cache_t * cachep, unsigned long flags)
{
	struct socket_alloc *ei = (struct socket_alloc *) foo;
	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
		SLAB_CTOR_CONSTRUCTOR)
		inode_init_once(&ei->vfs_inode);
}

static int init_inodecache(void)
{
	sock_inode_cachep = kmem_cache_create("sock_inode_cache",
				sizeof(struct socket_alloc),
				0, SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT,
				init_once, NULL);
	if (sock_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}



static int sock_no_open(struct inode *irrelevant, struct file *dontcare)
{
	return -ENXIO;
}

struct file_operations bad_sock_fops = {
	.owner = THIS_MODULE,
	.open = sock_no_open,
};













extern void sk_init(void);

void __init sock_init(void)
{
	// Initialize sock SLAB cache.
	sk_init();

#ifdef SLAB_SKB
	// Initialize skbuff SLAB cache 
	skb_init();
#endif

	// Initialize the protocols module. 
	init_inodecache();
}