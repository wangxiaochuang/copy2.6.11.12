#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "security.h"

#include "policydb.h"
#include "conditional.h"
#include "mls.h"

int policydb_context_isvalid(struct policydb *p, struct context *c)
{
	struct role_datum *role;
	struct user_datum *usrdatum;

	if (!c->role || c->role > p->p_roles.nprim)
		return 0;

	if (!c->user || c->user > p->p_users.nprim)
		return 0;

	if (!c->type || c->type > p->p_types.nprim)
		return 0;

	if (c->role != OBJECT_R_VAL) {
		/*
		 * Role must be authorized for the type.
		 */
		role = p->role_val_to_struct[c->role - 1];
		if (!ebitmap_get_bit(&role->types,
				     c->type - 1))
			/* role may not be associated with type */
			return 0;

		/*
		 * User must be authorized for the role.
		 */
		usrdatum = p->user_val_to_struct[c->user - 1];
		if (!usrdatum)
			return 0;

		if (!ebitmap_get_bit(&usrdatum->roles,
				     c->role - 1))
			/* user may not be associated with role */
			return 0;
	}

	if (!mls_context_isvalid(p, c))
		return 0;

	return 1;
}