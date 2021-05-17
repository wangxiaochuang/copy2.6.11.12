#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <asm/semaphore.h>
#include <linux/slab.h>

#include "security.h"
#include "conditional.h"

void cond_compute_av(struct avtab *ctab, struct avtab_key *key, struct av_decision *avd)
{
	struct avtab_node *node;

	if(!ctab || !key || !avd)
		return;

	for(node = avtab_search_node(ctab, key, AVTAB_AV); node != NULL;
				node = avtab_search_node_next(node, AVTAB_AV)) {
		if ( (__u32) (AVTAB_ALLOWED|AVTAB_ENABLED) ==
		     (node->datum.specified & (AVTAB_ALLOWED|AVTAB_ENABLED)))
			avd->allowed |= avtab_allowed(&node->datum);
		if ( (__u32) (AVTAB_AUDITDENY|AVTAB_ENABLED) ==
		     (node->datum.specified & (AVTAB_AUDITDENY|AVTAB_ENABLED)))
			/* Since a '0' in an auditdeny mask represents a
			 * permission we do NOT want to audit (dontaudit), we use
			 * the '&' operand to ensure that all '0's in the mask
			 * are retained (much unlike the allow and auditallow cases).
			 */
			avd->auditdeny &= avtab_auditdeny(&node->datum);
		if ( (__u32) (AVTAB_AUDITALLOW|AVTAB_ENABLED) ==
		     (node->datum.specified & (AVTAB_AUDITALLOW|AVTAB_ENABLED)))
			avd->auditallow |= avtab_auditallow(&node->datum);
	}
	return;
}