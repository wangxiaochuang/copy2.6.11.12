#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/keyctl.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm/uaccess.h>
#include "internal.h"

struct key_user root_key_user = {
	.usage		= ATOMIC_INIT(3),
	.consq		= LIST_HEAD_INIT(root_key_user.consq),
	.lock		= SPIN_LOCK_UNLOCKED,
	.nkeys		= ATOMIC_INIT(2),
	.nikeys		= ATOMIC_INIT(2),
	.uid		= 0,
};

struct key root_user_keyring = {
	.usage		= ATOMIC_INIT(1),
	.serial		= 2,
	.type		= &key_type_keyring,
	.user		= &root_key_user,
	.lock		= RW_LOCK_UNLOCKED,
	.sem		= __RWSEM_INITIALIZER(root_user_keyring.sem),
	.perm		= KEY_USR_ALL,
	.flags		= KEY_FLAG_INSTANTIATED,
	.description	= "_uid.0",
#ifdef KEY_DEBUGGING
	.magic		= KEY_DEBUG_MAGIC,
#endif
};

struct key root_session_keyring = {
	.usage		= ATOMIC_INIT(1),
	.serial		= 1,
	.type		= &key_type_keyring,
	.user		= &root_key_user,
	.lock		= RW_LOCK_UNLOCKED,
	.sem		= __RWSEM_INITIALIZER(root_session_keyring.sem),
	.perm		= KEY_USR_ALL,
	.flags		= KEY_FLAG_INSTANTIATED,
	.description	= "_uid_ses.0",
#ifdef KEY_DEBUGGING
	.magic		= KEY_DEBUG_MAGIC,
#endif
};

/*****************************************************************************/
/*
 * install a fresh process keyring, discarding the old one
 */
static int install_process_keyring(struct task_struct *tsk)
{
	return 0;
}

/*****************************************************************************/
/*
 * copy the keys for fork
 */
int copy_keys(unsigned long clone_flags, struct task_struct *tsk)
{
	int ret = 0;

	key_check(tsk->session_keyring);
	key_check(tsk->process_keyring);
	key_check(tsk->thread_keyring);

	if (tsk->session_keyring)
		atomic_inc(&tsk->session_keyring->usage);

	if (tsk->process_keyring) {
		if (clone_flags & CLONE_THREAD) {
			atomic_inc(&tsk->process_keyring->usage);
		}
		else {
			tsk->process_keyring = NULL;
			ret = install_process_keyring(tsk);
		}
	}

	tsk->thread_keyring = NULL;
	return ret;
}

/*****************************************************************************/
/*
 * dispose of keys upon exit
 */
void exit_keys(struct task_struct *tsk)
{
	key_put(tsk->session_keyring);
	key_put(tsk->process_keyring);
	key_put(tsk->thread_keyring);

} /* end exit_keys() */