#include <linux/module.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>
#include <linux/ptrace.h>
#include <linux/security.h>

#include <asm/pgtable.h>
#include <asm/uaccess.h>

void __ptrace_link(task_t *child, task_t *new_parent)
{
	if (!list_empty(&child->ptrace_list))
		BUG();
	if (child->parent == new_parent)
		return;
	list_add(&child->ptrace_list, &child->parent->ptrace_children);
	REMOVE_LINKS(child);
	child->parent = new_parent;
	SET_LINKS(child);
}

void ptrace_untrace(task_t *child)
{
}

void __ptrace_unlink(task_t *child)
{
}