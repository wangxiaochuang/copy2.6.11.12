#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/err.h>
#include "internal.h"

static void key_cleanup(void *data);
static DECLARE_WORK(key_cleanup_task, key_cleanup, NULL);

/*****************************************************************************/
/*
 * do cleaning up in process context so that we don't have to disable
 * interrupts all over the place
 */
static void key_cleanup(void *data)
{
	panic("in key_cleanup function");
}

/*****************************************************************************/
/*
 * dispose of a reference to a key
 * - when all the references are gone, we schedule the cleanup task to come and
 *   pull it out of the tree in definite process context
 */
void key_put(struct key *key)
{
	if (key) {
		key_check(key);

		if (atomic_dec_and_test(&key->usage))
			schedule_work(&key_cleanup_task);
	}

} /* end key_put() */

EXPORT_SYMBOL(key_put);