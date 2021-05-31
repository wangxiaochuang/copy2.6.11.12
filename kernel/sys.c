#include <linux/config.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/utsname.h>
#include <linux/mman.h>
#include <linux/smp_lock.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/prctl.h>
#include <linux/init.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/device.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/security.h>
#include <linux/dcookies.h>
#include <linux/suspend.h>
#include <linux/tty.h>

#include <linux/compat.h>
#include <linux/syscalls.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>

DEFINE_RWLOCK(notifier_lock);

/**
 *	notifier_chain_register	- Add notifier to a notifier chain
 *	@list: Pointer to root list pointer
 *	@n: New entry in notifier chain
 *
 *	Adds a notifier to a notifier chain.
 *
 *	Currently always returns zero.
 */
 
int notifier_chain_register(struct notifier_block **list, struct notifier_block *n)
{
	write_lock(&notifier_lock);
	while (*list) {
		if (n->priority > (*list)->priority)
			break;
		list = &((*list)->next);
	}
	n->next = *list;
	*list = n;
	write_unlock(&notifier_lock);
	return 0;
}

int notifier_call_chain(struct notifier_block **n, unsigned long val, void *v)
{
	int ret=NOTIFY_DONE;
	struct notifier_block *nb = *n;

	while(nb)
	{
		ret=nb->notifier_call(nb,val,v);
		if(ret&NOTIFY_STOP_MASK)
		{
			return ret;
		}
		nb=nb->next;
	}
	return ret;
}

EXPORT_SYMBOL(notifier_call_chain);

struct group_info init_groups = { .usage = ATOMIC_INIT(2) };







void groups_free(struct group_info *group_info)
{
	if (group_info->blocks[0] != group_info->small_block) {
		int i;
		for (i = 0; i < group_info->nblocks; i++)
			free_page((unsigned long)group_info->blocks[i]);
	}
	kfree(group_info);
}

EXPORT_SYMBOL(groups_free);


/* a simple bsearch */
static int groups_search(struct group_info *group_info, gid_t grp)
{
	int left, right;

	if (!group_info)
		return 0;

	left = 0;
	right = group_info->ngroups;
	while (left < right) {
		int mid = (left+right)/2;
		int cmp = grp - GROUP_AT(group_info, mid);
		if (cmp > 0)
			left = mid + 1;
		else if (cmp < 0)
			right = mid;
		else
			return 1;
	}
	return 0;
}

/*
 * Check whether we're fsgid/egid or in the supplemental group..
 */
int in_group_p(gid_t grp)
{
	int retval = 1;
	if (grp != current->fsgid) {
		get_group_info(current->group_info);
		retval = groups_search(current->group_info, grp);
		put_group_info(current->group_info);
	}
	return retval;
}

EXPORT_SYMBOL(in_group_p);

int in_egroup_p(gid_t grp)
{
	int retval = 1;
	if (grp != current->egid) {
		get_group_info(current->group_info);
		retval = groups_search(current->group_info, grp);
		put_group_info(current->group_info);
	}
	return retval;
}

EXPORT_SYMBOL(in_egroup_p);