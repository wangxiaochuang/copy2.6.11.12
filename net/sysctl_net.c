#include <linux/config.h>
#include <linux/mm.h>
#include <linux/sysctl.h>

#ifdef CONFIG_INET
extern struct ctl_table ipv4_table[];
#endif

extern struct ctl_table core_table[];

#ifdef CONFIG_NET
extern struct ctl_table ether_table[];
#endif

#ifdef CONFIG_TR
extern struct ctl_table tr_table[];
#endif

struct ctl_table net_table[] = {
    { 0 },
};