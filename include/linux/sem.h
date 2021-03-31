#ifndef _LINUX_SEM_H
#define _LINUX_SEM_H

#include <linux/spinlock.h>
#include <asm/atomic.h>

struct sem_undo {
	struct sem_undo *	proc_next;	/* next entry on this process */
	struct sem_undo *	id_next;	/* next entry on this semaphore set */
	int			semid;		/* semaphore set identifier */
	short *			semadj;		/* array of adjustments, one per semaphore */
};

/* sem_undo_list controls shared access to the list of sem_undo structures
 * that may be shared among all a CLONE_SYSVSEM task group.
 */ 
struct sem_undo_list {
	atomic_t	refcnt;
	spinlock_t	lock;
	struct sem_undo	*proc_list;
};

struct sysv_sem {
	struct sem_undo_list *undo_list;
};

#endif