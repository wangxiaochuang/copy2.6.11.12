#include <linux/config.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/poll.h>
#include <linux/tcp.h>
#include <linux/init.h>

#include <asm/uaccess.h>
#include <asm/system.h>

#include <linux/netdevice.h>
#include <net/protocol.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/xfrm.h>
#include <linux/ipsec.h>

#include <linux/filter.h>

#ifdef CONFIG_INET
#include <net/tcp.h>
#endif

#define _SK_MEM_PACKETS		256
#define _SK_MEM_OVERHEAD	(sizeof(struct sk_buff) + 256)
#define SK_WMEM_MAX		(_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)
#define SK_RMEM_MAX		(_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)

/* Run time adjustable parameters. */
__u32 sysctl_wmem_max = SK_WMEM_MAX;
__u32 sysctl_rmem_max = SK_RMEM_MAX;
__u32 sysctl_wmem_default = SK_WMEM_MAX;
__u32 sysctl_rmem_default = SK_RMEM_MAX;





static kmem_cache_t *sk_cachep;

void __init sk_init(void)
{
	sk_cachep = kmem_cache_create("sock", sizeof(struct sock), 0,
				      SLAB_HWCACHE_ALIGN, NULL, NULL);
	if (!sk_cachep)
		printk(KERN_CRIT "sk_init: Cannot create sock SLAB cache!");
    
    if (num_physpages <= 4096) {
		sysctl_wmem_max = 32767;
		sysctl_rmem_max = 32767;
		sysctl_wmem_default = 32767;
		sysctl_rmem_default = 32767;
	} else if (num_physpages >= 131072) {
		sysctl_wmem_max = 131071;
		sysctl_rmem_max = 131071;
	}
}