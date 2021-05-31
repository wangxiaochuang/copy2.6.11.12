#include <linux/config.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/time.h>
#include <linux/smp_lock.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>
#include "util.h"

/* If CLONE_SYSVSEM is set, establish sharing of SEM_UNDO state between
 * parent and child tasks.
 *
 * See the notes above unlock_semundo() regarding the spin_lock_init()
 * in this code.  Initialize the undo_list->lock here instead of get_undo_list()
 * because of the reasoning in the comment above unlock_semundo.
 */

static inline int get_undo_list(struct sem_undo_list **undo_listp)
{
	struct sem_undo_list *undo_list;
	int size;

	undo_list = current->sysvsem.undo_list;
	if (!undo_list) {
		size = sizeof(struct sem_undo_list);
		undo_list = (struct sem_undo_list *) kmalloc(size, GFP_KERNEL);
		if (undo_list == NULL)
			return -ENOMEM;
		memset(undo_list, 0, size);
		/* don't initialize unodhd->lock here.  It's done
		 * in copy_semundo() instead.
		 */
		atomic_set(&undo_list->refcnt, 1);
		current->sysvsem.undo_list = undo_list;
	}
	*undo_listp = undo_list;
	return 0;
}

int copy_semundo(unsigned long clone_flags, struct task_struct *tsk)
{
	struct sem_undo_list *undo_list;
	int error;

	if (clone_flags & CLONE_SYSVSEM) {
		error = get_undo_list(&undo_list);
		if (error)
			return error;
		if (atomic_read(&undo_list->refcnt) == 1)
			spin_lock_init(&undo_list->lock);
		atomic_inc(&undo_list->refcnt);
		tsk->sysvsem.undo_list = undo_list;
	} else
		tsk->sysvsem.undo_list = NULL;

	return 0;
}

void exit_sem(struct task_struct *tsk)
{
	struct sem_undo_list *undo_list;
	struct sem_undo *u, **up;

	undo_list = tsk->sysvsem.undo_list;
	if (!undo_list)
		return;

	panic("in exit_sem function");
}