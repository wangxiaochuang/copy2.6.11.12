#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/key.h>

struct user_struct root_user = {
	.__count	= ATOMIC_INIT(1),
	.processes	= ATOMIC_INIT(1),
	.files		= ATOMIC_INIT(0),
	.sigpending	= ATOMIC_INIT(0),
	.mq_bytes	= 0,
	.locked_shm     = 0,
#ifdef CONFIG_KEYS
	.uid_keyring	= &root_user_keyring,
	.session_keyring = &root_session_keyring,
#endif
};