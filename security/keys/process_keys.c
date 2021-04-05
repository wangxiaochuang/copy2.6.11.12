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