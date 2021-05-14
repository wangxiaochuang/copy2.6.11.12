#include <linux/init.h>
#include <asm/atomic.h>
#include <asm/types.h>
#include <linux/mm.h>
#include <linux/module.h>

#include <linux/audit.h>

#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>

void audit_log(struct audit_context *ctx, const char *fmt, ...)
{
    printk("############ audit_log not implement\n");
}