#undef DEBUG

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/security.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/xattr.h>
#include <linux/hugetlb.h>
#include <linux/ptrace.h>
#include <linux/file.h>

struct security_operations dummy_security_ops;

void security_fixup_ops (struct security_operations *ops)
{
}