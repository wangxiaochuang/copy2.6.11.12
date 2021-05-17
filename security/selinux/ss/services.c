#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/audit.h>
#include <asm/semaphore.h>
#include "flask.h"
#include "avc.h"
#include "avc_ss.h"
#include "security.h"
#include "context.h"
#include "policydb.h"
#include "sidtab.h"
#include "services.h"
#include "conditional.h"
#include "mls.h"

unsigned int policydb_loaded_version;

static DEFINE_RWLOCK(policy_rwlock);
#define POLICY_RDLOCK read_lock(&policy_rwlock)
#define POLICY_WRLOCK write_lock_irq(&policy_rwlock)
#define POLICY_RDUNLOCK read_unlock(&policy_rwlock)
#define POLICY_WRUNLOCK write_unlock_irq(&policy_rwlock

struct sidtab sidtab;
struct policydb policydb;
int ss_initialized = 0;

static u32 latest_granting = 0;

static int constraint_expr_eval(struct context *scontext,
				struct context *tcontext,
				struct constraint_expr *cexpr)
{
	u32 val1, val2;
	struct context *c;
	struct role_datum *r1, *r2;
	struct constraint_expr *e;
	int s[CEXPR_MAXDEPTH];
	int sp = -1;

	for (e = cexpr; e; e = e->next) {
		switch (e->expr_type) {
		case CEXPR_NOT:
			BUG_ON(sp < 0);
			s[sp] = !s[sp];
			break;
		case CEXPR_AND:
			BUG_ON(sp < 1);
			sp--;
			s[sp] &= s[sp+1];
			break;
		case CEXPR_OR:
			BUG_ON(sp < 1);
			sp--;
			s[sp] |= s[sp+1];
			break;
		case CEXPR_ATTR:
			if (sp == (CEXPR_MAXDEPTH-1))
				return 0;
			switch (e->attr) {
			case CEXPR_USER:
				val1 = scontext->user;
				val2 = tcontext->user;
				break;
			case CEXPR_TYPE:
				val1 = scontext->type;
				val2 = tcontext->type;
				break;
			case CEXPR_ROLE:
				val1 = scontext->role;
				val2 = tcontext->role;
				r1 = policydb.role_val_to_struct[val1 - 1];
				r2 = policydb.role_val_to_struct[val2 - 1];
				switch (e->op) {
				case CEXPR_DOM:
					s[++sp] = ebitmap_get_bit(&r1->dominates,
								  val2 - 1);
					continue;
				case CEXPR_DOMBY:
					s[++sp] = ebitmap_get_bit(&r2->dominates,
								  val1 - 1);
					continue;
				case CEXPR_INCOMP:
					s[++sp] = ( !ebitmap_get_bit(&r1->dominates,
								     val2 - 1) &&
						    !ebitmap_get_bit(&r2->dominates,
								     val1 - 1) );
					continue;
				default:
					break;
				}
				break;
			default:
				BUG();
				return 0;
			}

			switch (e->op) {
			case CEXPR_EQ:
				s[++sp] = (val1 == val2);
				break;
			case CEXPR_NEQ:
				s[++sp] = (val1 != val2);
				break;
			default:
				BUG();
				return 0;
			}
			break;
		case CEXPR_NAMES:
			if (sp == (CEXPR_MAXDEPTH-1))
				return 0;
			c = scontext;
			if (e->attr & CEXPR_TARGET)
				c = tcontext;
			if (e->attr & CEXPR_USER)
				val1 = c->user;
			else if (e->attr & CEXPR_ROLE)
				val1 = c->role;
			else if (e->attr & CEXPR_TYPE)
				val1 = c->type;
			else {
				BUG();
				return 0;
			}

			switch (e->op) {
			case CEXPR_EQ:
				s[++sp] = ebitmap_get_bit(&e->names, val1 - 1);
				break;
			case CEXPR_NEQ:
				s[++sp] = !ebitmap_get_bit(&e->names, val1 - 1);
				break;
			default:
				BUG();
				return 0;
			}
			break;
		default:
			BUG();
			return 0;
		}
	}

	BUG_ON(sp != 0);
	return s[0];
}

static int context_struct_compute_av(struct context *scontext,
				     struct context *tcontext,
				     u16 tclass,
				     u32 requested,
				     struct av_decision *avd)
{
	struct constraint_node *constraint;
	struct role_allow *ra;
	struct avtab_key avkey;
	struct avtab_datum *avdatum;
	struct class_datum *tclass_datum;

    if (policydb_loaded_version < POLICYDB_VERSION_NLCLASS)
		if (tclass >= SECCLASS_NETLINK_ROUTE_SOCKET &&
		    tclass <= SECCLASS_NETLINK_DNRT_SOCKET)
			tclass = SECCLASS_NETLINK_SOCKET;

    if (!tclass || tclass > policydb.p_classes.nprim) {
		printk(KERN_ERR "security_compute_av:  unrecognized class %d\n",
		       tclass);
		return -EINVAL;
	}
	tclass_datum = policydb.class_val_to_struct[tclass - 1];

    avd->allowed = 0;
	avd->decided = 0xffffffff;
	avd->auditallow = 0;
	avd->auditdeny = 0xffffffff;
	avd->seqno = latest_granting;

	/*
	 * If a specific type enforcement rule was defined for
	 * this permission check, then use it.
	 */
	avkey.source_type = scontext->type;
	avkey.target_type = tcontext->type;
	avkey.target_class = tclass;
    avdatum = avtab_search(&policydb.te_avtab, &avkey, AVTAB_AV);
	if (avdatum) {
		if (avdatum->specified & AVTAB_ALLOWED)
			avd->allowed = avtab_allowed(avdatum);
		if (avdatum->specified & AVTAB_AUDITDENY)
			avd->auditdeny = avtab_auditdeny(avdatum);
		if (avdatum->specified & AVTAB_AUDITALLOW)
			avd->auditallow = avtab_auditallow(avdatum);
	}

    /* Check conditional av table for additional permissions */
	cond_compute_av(&policydb.te_cond_avtab, &avkey, avd);

	/*
	 * Remove any permissions prohibited by the MLS policy.
	 */
	mls_compute_av(scontext, tcontext, tclass_datum, &avd->allowed);

	/*
	 * Remove any permissions prohibited by a constraint.
	 */
	constraint = tclass_datum->constraints;
	while (constraint) {
		if ((constraint->permissions & (avd->allowed)) &&
		    !constraint_expr_eval(scontext, tcontext,
					  constraint->expr)) {
			avd->allowed = (avd->allowed) & ~(constraint->permissions);
		}
		constraint = constraint->next;
	}

    /*
	 * If checking process transition permission and the
	 * role is changing, then check the (current_role, new_role)
	 * pair.
	 */
	if (tclass == SECCLASS_PROCESS &&
	    (avd->allowed & (PROCESS__TRANSITION | PROCESS__DYNTRANSITION)) &&
	    scontext->role != tcontext->role) {
		for (ra = policydb.role_allow; ra; ra = ra->next) {
			if (scontext->role == ra->role &&
			    tcontext->role == ra->new_role)
				break;
		}
		if (!ra)
			avd->allowed = (avd->allowed) & ~(PROCESS__TRANSITION |
			                                PROCESS__DYNTRANSITION);
	}

	return 0;
}

int security_compute_av(u32 ssid,
			u32 tsid,
			u16 tclass,
			u32 requested,
			struct av_decision *avd)
{
    struct context *scontext = NULL, *tcontext = NULL;
	int rc = 0;

	if (!ss_initialized) {
		avd->allowed = requested;
		avd->decided = requested;
		avd->auditallow = 0;
		avd->auditdeny = 0xffffffff;
		avd->seqno = latest_granting;
		return 0;
	}

	POLICY_RDLOCK;

    scontext = sidtab_search(&sidtab, ssid);
	if (!scontext) {
		printk(KERN_ERR "security_compute_av:  unrecognized SID %d\n",
		       ssid);
		rc = -EINVAL;
		goto out;
	}
	tcontext = sidtab_search(&sidtab, tsid);
	if (!tcontext) {
		printk(KERN_ERR "security_compute_av:  unrecognized SID %d\n",
		       tsid);
		rc = -EINVAL;
		goto out;
	}

	rc = context_struct_compute_av(scontext, tcontext, tclass,
				       requested, avd);
out:
	POLICY_RDUNLOCK;
	return rc;
}

int context_struct_to_string(struct context *context, char **scontext, u32 *scontext_len)
{
	char *scontextp;

	*scontext = NULL;
	*scontext_len = 0;

	/* Compute the size of the context. */
	*scontext_len += strlen(policydb.p_user_val_to_name[context->user - 1]) + 1;
	*scontext_len += strlen(policydb.p_role_val_to_name[context->role - 1]) + 1;
	*scontext_len += strlen(policydb.p_type_val_to_name[context->type - 1]) + 1;
	*scontext_len += mls_compute_context_len(context);

	/* Allocate space for the context; caller must free this space. */
	scontextp = kmalloc(*scontext_len+1,GFP_ATOMIC);
	if (!scontextp) {
		return -ENOMEM;
	}
	*scontext = scontextp;

	/*
	 * Copy the user name, role name and type name into the context.
	 */
	sprintf(scontextp, "%s:%s:%s:",
		policydb.p_user_val_to_name[context->user - 1],
		policydb.p_role_val_to_name[context->role - 1],
		policydb.p_type_val_to_name[context->type - 1]);
	scontextp += strlen(policydb.p_user_val_to_name[context->user - 1]) +
	             1 + strlen(policydb.p_role_val_to_name[context->role - 1]) +
	             1 + strlen(policydb.p_type_val_to_name[context->type - 1]) + 1;

	mls_sid_to_context(context, &scontextp);

	scontextp--;
	*scontextp = 0;

	return 0;
}

#include "initial_sid_to_string.h"

int security_context_to_sid(char *scontext, u32 scontext_len, u32 *sid)
{
	char *scontext2;
	struct context context;
	struct role_datum *role;
	struct type_datum *typdatum;
	struct user_datum *usrdatum;
	char *scontextp, *p, oldc;
	int rc = 0;

	if (!ss_initialized) {
		int i;

		for (i = 1; i < SECINITSID_NUM; i++) {
			if (!strcmp(initial_sid_to_string[i], scontext)) {
				*sid = i;
				goto out;
			}
		}
		*sid = SECINITSID_KERNEL;
		goto out;
	}
	*sid = SECSID_NULL;

	/* Copy the string so that we can modify the copy as we parse it.
	   The string should already by null terminated, but we append a
	   null suffix to the copy to avoid problems with the existing
	   attr package, which doesn't view the null terminator as part
	   of the attribute value. */
	scontext2 = kmalloc(scontext_len+1,GFP_KERNEL);
	if (!scontext2) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(scontext2, scontext, scontext_len);
	scontext2[scontext_len] = 0;

	context_init(&context);
	*sid = SECSID_NULL;

	POLICY_RDLOCK;

	/* Parse the security context. */

	rc = -EINVAL;
	scontextp = (char *) scontext2;

	/* Extract the user. */
	p = scontextp;
	while (*p && *p != ':')
		p++;

	if (*p == 0)
		goto out_unlock;

	*p++ = 0;

	usrdatum = hashtab_search(policydb.p_users.table, scontextp);
	if (!usrdatum)
		goto out_unlock;

	context.user = usrdatum->value;

	/* Extract role. */
	scontextp = p;
	while (*p && *p != ':')
		p++;

	if (*p == 0)
		goto out_unlock;

	*p++ = 0;

	role = hashtab_search(policydb.p_roles.table, scontextp);
	if (!role)
		goto out_unlock;
	context.role = role->value;

	/* Extract type. */
	scontextp = p;
	while (*p && *p != ':')
		p++;
	oldc = *p;
	*p++ = 0;

	typdatum = hashtab_search(policydb.p_types.table, scontextp);
	if (!typdatum)
		goto out_unlock;

	context.type = typdatum->value;

	rc = mls_context_to_sid(oldc, &p, &context);
	if (rc)
		goto out_unlock;

	if ((p - scontext2) < scontext_len) {
		rc = -EINVAL;
		goto out_unlock;
	}

	/* Check the validity of the new context. */
	if (!policydb_context_isvalid(&policydb, &context)) {
		rc = -EINVAL;
		goto out_unlock;
	}
	/* Obtain the new sid. */
	rc = sidtab_context_to_sid(&sidtab, &context, sid);
out_unlock:
	POLICY_RDUNLOCK;
	context_destroy(&context);
	kfree(scontext2);
out:
	return rc;
}


static int compute_sid_handle_invalid_context(
	struct context *scontext,
	struct context *tcontext,
	u16 tclass,
	struct context *newcontext)
{
	char *s = NULL, *t = NULL, *n = NULL;
	u32 slen, tlen, nlen;

	if (context_struct_to_string(scontext, &s, &slen) < 0)
		goto out;
	if (context_struct_to_string(tcontext, &t, &tlen) < 0)
		goto out;
	if (context_struct_to_string(newcontext, &n, &nlen) < 0)
		goto out;
	audit_log(current->audit_context,
		  "security_compute_sid:  invalid context %s"
		  " for scontext=%s"
		  " tcontext=%s"
		  " tclass=%s",
		  n, s, t, policydb.p_class_val_to_name[tclass-1]);
out:
	kfree(s);
	kfree(t);
	kfree(n);
	if (!selinux_enforcing)
		return 0;
	return -EACCES;
}

static int security_compute_sid(u32 ssid,
				u32 tsid,
				u16 tclass,
				u32 specified,
				u32 *out_sid)
{
	struct context *scontext = NULL, *tcontext = NULL, newcontext;
	struct role_trans *roletr = NULL;
	struct avtab_key avkey;
	struct avtab_datum *avdatum;
	struct avtab_node *node;
	unsigned int type_change = 0;
	int rc = 0;

	if (!ss_initialized) {
		switch (tclass) {
		case SECCLASS_PROCESS:
			*out_sid = ssid;
			break;
		default:
			*out_sid = tsid;
			break;
		}
		goto out;
	}

	POLICY_RDLOCK;

	scontext = sidtab_search(&sidtab, ssid);
	if (!scontext) {
		printk(KERN_ERR "security_compute_sid:  unrecognized SID %d\n",
		       ssid);
		rc = -EINVAL;
		goto out_unlock;
	}
	tcontext = sidtab_search(&sidtab, tsid);
	if (!tcontext) {
		printk(KERN_ERR "security_compute_sid:  unrecognized SID %d\n",
		       tsid);
		rc = -EINVAL;
		goto out_unlock;
	}

	context_init(&newcontext);

	/* Set the user identity. */
	switch (specified) {
	case AVTAB_TRANSITION:
	case AVTAB_CHANGE:
		/* Use the process user identity. */
		newcontext.user = scontext->user;
		break;
	case AVTAB_MEMBER:
		/* Use the related object owner. */
		newcontext.user = tcontext->user;
		break;
	}

	/* Set the role and type to default values. */
	switch (tclass) {
	case SECCLASS_PROCESS:
		/* Use the current role and type of process. */
		newcontext.role = scontext->role;
		newcontext.type = scontext->type;
		break;
	default:
		/* Use the well-defined object role. */
		newcontext.role = OBJECT_R_VAL;
		/* Use the type of the related object. */
		newcontext.type = tcontext->type;
	}

	/* Look for a type transition/member/change rule. */
	avkey.source_type = scontext->type;
	avkey.target_type = tcontext->type;
	avkey.target_class = tclass;
	avdatum = avtab_search(&policydb.te_avtab, &avkey, AVTAB_TYPE);

	/* If no permanent rule, also check for enabled conditional rules */
	if(!avdatum) {
		node = avtab_search_node(&policydb.te_cond_avtab, &avkey, specified);
		for (; node != NULL; node = avtab_search_node_next(node, specified)) {
			if (node->datum.specified & AVTAB_ENABLED) {
				avdatum = &node->datum;
				break;
			}
		}
	}

	type_change = (avdatum && (avdatum->specified & specified));
	if (type_change) {
		/* Use the type from the type transition/member/change rule. */
		switch (specified) {
		case AVTAB_TRANSITION:
			newcontext.type = avtab_transition(avdatum);
			break;
		case AVTAB_MEMBER:
			newcontext.type = avtab_member(avdatum);
			break;
		case AVTAB_CHANGE:
			newcontext.type = avtab_change(avdatum);
			break;
		}
	}

	/* Check for class-specific changes. */
	switch (tclass) {
	case SECCLASS_PROCESS:
		if (specified & AVTAB_TRANSITION) {
			/* Look for a role transition rule. */
			for (roletr = policydb.role_tr; roletr;
			     roletr = roletr->next) {
				if (roletr->role == scontext->role &&
				    roletr->type == tcontext->type) {
					/* Use the role transition rule. */
					newcontext.role = roletr->new_role;
					break;
				}
			}
		}

		if (!type_change && !roletr) {
			/* No change in process role or type. */
			*out_sid = ssid;
			goto out_unlock;

		}
		break;
	default:
		if (!type_change &&
		    (newcontext.user == tcontext->user) &&
		    mls_context_cmp(scontext, tcontext)) {
                        /* No change in object type, owner,
			   or MLS attributes. */
			*out_sid = tsid;
			goto out_unlock;
		}
		break;
	}

	/* Set the MLS attributes.
	   This is done last because it may allocate memory. */
	rc = mls_compute_sid(scontext, tcontext, tclass, specified, &newcontext);
	if (rc)
		goto out_unlock;

	/* Check the validity of the context. */
	if (!policydb_context_isvalid(&policydb, &newcontext)) {
		rc = compute_sid_handle_invalid_context(scontext,
							tcontext,
							tclass,
							&newcontext);
		if (rc)
			goto out_unlock;
	}
	/* Obtain the sid for the context. */
	rc = sidtab_context_to_sid(&sidtab, &newcontext, out_sid);
out_unlock:
	POLICY_RDUNLOCK;
	context_destroy(&newcontext);
out:
	return rc;
}

int security_transition_sid(u32 ssid,
			    u32 tsid,
			    u16 tclass,
			    u32 *out_sid)
{
	return security_compute_sid(ssid, tsid, tclass, AVTAB_TRANSITION, out_sid);
}

int security_genfs_sid(const char *fstype,
	               char *path,
		       u16 sclass,
		       u32 *sid)
{
	int len;
	struct genfs *genfs;
	struct ocontext *c;
	int rc = 0, cmp = 0;

	POLICY_RDLOCK;

	for (genfs = policydb.genfs; genfs; genfs = genfs->next) {
		cmp = strcmp(fstype, genfs->fstype);
		if (cmp <= 0)
			break;
	}

	if (!genfs || cmp) {
		*sid = SECINITSID_UNLABELED;
		rc = -ENOENT;
		goto out;
	}

	for (c = genfs->head; c; c = c->next) {
		len = strlen(c->u.name);
		if ((!c->v.sclass || sclass == c->v.sclass) &&
		    (strncmp(c->u.name, path, len) == 0))
			break;
	}

	if (!c) {
		*sid = SECINITSID_UNLABELED;
		rc = -ENOENT;
		goto out;
	}

	if (!c->sid[0]) {
		rc = sidtab_context_to_sid(&sidtab,
					   &c->context[0],
					   &c->sid[0]);
		if (rc)
			goto out;
	}

	*sid = c->sid[0];
out:
	POLICY_RDUNLOCK;
	return rc;
}