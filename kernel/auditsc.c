#include <linux/init.h>
#include <asm/atomic.h>
#include <asm/types.h>
#include <linux/mm.h>
#include <linux/module.h>

#include <linux/audit.h>
#include <linux/personality.h>
#include <linux/time.h>
#include <asm/unistd.h>

/* 0 = no checking
   1 = put_count checking
   2 = verbose put_count checking
*/
#define AUDIT_DEBUG 0

/* No syscall auditing will take place unless audit_enabled != 0. */
extern int audit_enabled;

/* AUDIT_NAMES is the number of slots we reserve in the audit_context
 * for saving names from getname(). */
#define AUDIT_NAMES    20

/* AUDIT_NAMES_RESERVED is the number of slots we reserve in the
 * audit_context from being used for nameless inodes from
 * path_lookup. */
#define AUDIT_NAMES_RESERVED 7

/* At task start time, the audit_state is set in the audit_context using
   a per-task filter.  At syscall entry, the audit_state is augmented by
   the syscall filter. */
enum audit_state {
	AUDIT_DISABLED,		/* Do not create per-task audit_context.
				 * No syscall-specific audit records can
				 * be generated. */
	AUDIT_SETUP_CONTEXT,	/* Create the per-task audit_context,
				 * but don't necessarily fill it in at
				 * syscall entry time (i.e., filter
				 * instead). */
	AUDIT_BUILD_CONTEXT,	/* Create the per-task audit_context,
				 * and always fill it in at syscall
				 * entry time.  This makes a full
				 * syscall record available if some
				 * other part of the kernel decides it
				 * should be recorded. */
	AUDIT_RECORD_CONTEXT	/* Create the per-task audit_context,
				 * always fill it in at syscall entry
				 * time, and always write out the audit
				 * record at syscall exit time.  */
};

/* When fs/namei.c:getname() is called, we store the pointer in name and
 * we don't let putname() free it (instead we free all of the saved
 * pointers at syscall exit time).
 *
 * Further, in fs/namei.c:path_lookup() we store the inode and device. */
struct audit_names {
	const char	*name;
	unsigned long	ino;
	dev_t		rdev;
};

/* The per-task audit context. */
struct audit_context {
	int		    in_syscall;	/* 1 if task is in a syscall */
	enum audit_state    state;
	unsigned int	    serial;     /* serial number for record */
	struct timespec	    ctime;      /* time of syscall entry */
	uid_t		    loginuid;   /* login uid (identity) */
	int		    major;      /* syscall number */
	unsigned long	    argv[4];    /* syscall arguments */
	int		    return_valid; /* return code is valid */
	int		    return_code;/* syscall return code */
	int		    auditable;  /* 1 if record should be written */
	int		    name_count;
	struct audit_names  names[AUDIT_NAMES];
	struct audit_context *previous; /* For nested syscalls */

				/* Save things to print about task_struct */
	pid_t		    pid;
	uid_t		    uid, euid, suid, fsuid;
	gid_t		    gid, egid, sgid, fsgid;
	unsigned long	    personality;

#if AUDIT_DEBUG
	int		    put_count;
	int		    ino_count;
#endif
};

				/* Public API */
/* There are three lists of rules -- one to search at task creation
 * time, one to search at syscall entry time, and another to search at
 * syscall exit time. */
static LIST_HEAD(audit_tsklist);
static LIST_HEAD(audit_entlist);
static LIST_HEAD(audit_extlist);

struct audit_entry {
	struct list_head  list;
	struct rcu_head   rcu;
	struct audit_rule rule;
};


/* Compare a task_struct with an audit_rule.  Return 1 on match, 0
 * otherwise. */
static int audit_filter_rules(struct task_struct *tsk,
			      struct audit_rule *rule,
			      struct audit_context *ctx,
			      enum audit_state *state)
{
	int i, j;

	for (i = 0; i < rule->field_count; i++) {
		u32 field  = rule->fields[i] & ~AUDIT_NEGATE;
		u32 value  = rule->values[i];
		int result = 0;

		switch (field) {
		case AUDIT_PID:
			result = (tsk->pid == value);
			break;
		case AUDIT_UID:
			result = (tsk->uid == value);
			break;
		case AUDIT_EUID:
			result = (tsk->euid == value);
			break;
		case AUDIT_SUID:
			result = (tsk->suid == value);
			break;
		case AUDIT_FSUID:
			result = (tsk->fsuid == value);
			break;
		case AUDIT_GID:
			result = (tsk->gid == value);
			break;
		case AUDIT_EGID:
			result = (tsk->egid == value);
			break;
		case AUDIT_SGID:
			result = (tsk->sgid == value);
			break;
		case AUDIT_FSGID:
			result = (tsk->fsgid == value);
			break;
		case AUDIT_PERS:
			result = (tsk->personality == value);
			break;

		case AUDIT_EXIT:
			if (ctx && ctx->return_valid)
				result = (ctx->return_code == value);
			break;
		case AUDIT_SUCCESS:
			if (ctx && ctx->return_valid)
				result = (ctx->return_code >= 0);
			break;
		case AUDIT_DEVMAJOR:
			if (ctx) {
				for (j = 0; j < ctx->name_count; j++) {
					if (MAJOR(ctx->names[j].rdev)==value) {
						++result;
						break;
					}
				}
			}
			break;
		case AUDIT_DEVMINOR:
			if (ctx) {
				for (j = 0; j < ctx->name_count; j++) {
					if (MINOR(ctx->names[j].rdev)==value) {
						++result;
						break;
					}
				}
			}
			break;
		case AUDIT_INODE:
			if (ctx) {
				for (j = 0; j < ctx->name_count; j++) {
					if (ctx->names[j].ino == value) {
						++result;
						break;
					}
				}
			}
			break;
		case AUDIT_LOGINUID:
			result = 0;
			if (ctx)
				result = (ctx->loginuid == value);
			break;
		case AUDIT_ARG0:
		case AUDIT_ARG1:
		case AUDIT_ARG2:
		case AUDIT_ARG3:
			if (ctx)
				result = (ctx->argv[field-AUDIT_ARG0]==value);
			break;
		}

		if (rule->fields[i] & AUDIT_NEGATE)
			result = !result;
		if (!result)
			return 0;
	}
	switch (rule->action) {
	case AUDIT_NEVER:    *state = AUDIT_DISABLED;	    break;
	case AUDIT_POSSIBLE: *state = AUDIT_BUILD_CONTEXT;  break;
	case AUDIT_ALWAYS:   *state = AUDIT_RECORD_CONTEXT; break;
	}
	return 1;
}

static enum audit_state audit_filter_task(struct task_struct *tsk)
{
	struct audit_entry *e;
	enum audit_state   state;

	rcu_read_lock();
	list_for_each_entry_rcu(e, &audit_tsklist, list) {
		if (audit_filter_rules(tsk, &e->rule, NULL, &state)) {
			rcu_read_unlock();
			return state;
		}
	}
	rcu_read_unlock();
	return AUDIT_BUILD_CONTEXT;
}

static enum audit_state audit_filter_syscall(struct task_struct *tsk,
					     struct audit_context *ctx,
					     struct list_head *list)
{
	struct audit_entry *e;
	enum audit_state   state;
	int		   word = AUDIT_WORD(ctx->major);
	int		   bit  = AUDIT_BIT(ctx->major);

	rcu_read_lock();
	list_for_each_entry_rcu(e, list, list) {
		if ((e->rule.mask[word] & bit) == bit
 		    && audit_filter_rules(tsk, &e->rule, ctx, &state)) {
			rcu_read_unlock();
			return state;
		}
	}
	rcu_read_unlock();
	return AUDIT_BUILD_CONTEXT;
}

static inline struct audit_context *audit_get_context(struct task_struct *tsk,
						      int return_valid,
						      int return_code)
{
	struct audit_context *context = tsk->audit_context;

	if (likely(!context))
		return NULL;
	context->return_valid = return_valid;
	context->return_code  = return_code;

	if (context->in_syscall && !context->auditable) {
		enum audit_state state;
		state = audit_filter_syscall(tsk, context, &audit_extlist);
		if (state == AUDIT_RECORD_CONTEXT)
			context->auditable = 1;
	}

	context->pid = tsk->pid;
	context->uid = tsk->uid;
	context->gid = tsk->gid;
	context->euid = tsk->euid;
	context->suid = tsk->suid;
	context->fsuid = tsk->fsuid;
	context->egid = tsk->egid;
	context->sgid = tsk->sgid;
	context->fsgid = tsk->fsgid;
	context->personality = tsk->personality;
	tsk->audit_context = NULL;
	return context;
}

static inline void audit_free_names(struct audit_context *context)
{
	int i;

	for (i = 0; i < context->name_count; i++)
		if (context->names[i].name)
			__putname(context->names[i].name);
	context->name_count = 0;
}

static inline void audit_zero_context(struct audit_context *context,
				      enum audit_state state)
{
	uid_t loginuid = context->loginuid;

	memset(context, 0, sizeof(*context));
	context->state      = state;
	context->loginuid   = loginuid;
}

static inline struct audit_context *audit_alloc_context(enum audit_state state)
{
	struct audit_context *context;

	if (!(context = kmalloc(sizeof(*context), GFP_KERNEL)))
		return NULL;
	audit_zero_context(context, state);
	return context;
}

/* Filter on the task information and allocate a per-task audit context
 * if necessary.  Doing so turns on system call auditing for the
 * specified task.  This is called from copy_process, so no lock is
 * needed. */
int audit_alloc(struct task_struct *tsk)
{
    struct audit_context *context;
	enum audit_state     state;

	if (likely(!audit_enabled))
		return 0; /* Return if not auditing. */

	state = audit_filter_task(tsk);
	if (likely(state == AUDIT_DISABLED))
		return 0;

	if (!(context = audit_alloc_context(state))) {
		audit_log_lost("out of memory in audit_alloc");
		return -ENOMEM;
	}

				/* Preserve login uid */
	context->loginuid = -1;
	if (current->audit_context)
		context->loginuid = current->audit_context->loginuid;

	tsk->audit_context  = context;
	set_tsk_thread_flag(tsk, TIF_SYSCALL_AUDIT);
	return 0;
}

static inline void audit_free_context(struct audit_context *context)
{
	struct audit_context *previous;
	int		     count = 0;

	do {
		previous = context->previous;
		if (previous || (count &&  count < 10)) {
			++count;
			printk(KERN_ERR "audit(:%d): major=%d name_count=%d:"
			       " freeing multiple contexts (%d)\n",
			       context->serial, context->major,
			       context->name_count, count);
		}
		audit_free_names(context);
		kfree(context);
		context  = previous;
	} while (context);
	if (count >= 10)
		printk(KERN_ERR "audit: freed %d contexts\n", count);
}

static void audit_log_exit(struct audit_context *context)
{
	int i;
	struct audit_buffer *ab;

	ab = audit_log_start(context);
	if (!ab)
		return;		/* audit_panic has been called */
	audit_log_format(ab, "syscall=%d", context->major);
	if (context->personality != PER_LINUX)
		audit_log_format(ab, " per=%lx", context->personality);
	if (context->return_valid)
		audit_log_format(ab, " exit=%d", context->return_code);
	audit_log_format(ab,
		  " a0=%lx a1=%lx a2=%lx a3=%lx items=%d"
		  " pid=%d loginuid=%d uid=%d gid=%d"
		  " euid=%d suid=%d fsuid=%d"
		  " egid=%d sgid=%d fsgid=%d",
		  context->argv[0],
		  context->argv[1],
		  context->argv[2],
		  context->argv[3],
		  context->name_count,
		  context->pid,
		  context->loginuid,
		  context->uid,
		  context->gid,
		  context->euid, context->suid, context->fsuid,
		  context->egid, context->sgid, context->fsgid);
	audit_log_end(ab);
	for (i = 0; i < context->name_count; i++) {
		ab = audit_log_start(context);
		if (!ab)
			continue; /* audit_panic has been called */
		audit_log_format(ab, "item=%d", i);
		if (context->names[i].name)
			audit_log_format(ab, " name=%s",
					 context->names[i].name);
		if (context->names[i].ino != (unsigned long)-1)
			audit_log_format(ab, " inode=%lu",
					 context->names[i].ino);
		/* FIXME: should use format_dev_t, but ab structure is
		 * opaque. */
		if (context->names[i].rdev != -1)
			audit_log_format(ab, " dev=%02x:%02x",
					 MAJOR(context->names[i].rdev),
					 MINOR(context->names[i].rdev));
		audit_log_end(ab);
	}
}

/* Free a per-task audit context.  Called from copy_process and
 * __put_task_struct. */
void audit_free(struct task_struct *tsk)
{
	struct audit_context *context;

	task_lock(tsk);
	context = audit_get_context(tsk, 0, 0);
	task_unlock(tsk);

	if (likely(!context))
		return;

	/* Check for system calls that do not go through the exit
	 * function (e.g., exit_group), then free context block. */
	if (context->in_syscall && context->auditable)
		audit_log_exit(context);

	audit_free_context(context);
}


/* Add a name to the list.  Called from fs/namei.c:getname(). */
void audit_getname(const char *name)
{
	struct audit_context *context = current->audit_context;

	BUG_ON(!context);
	if (!context->in_syscall) {
		return;
	}
	BUG_ON(context->name_count >= AUDIT_NAMES);
	context->names[context->name_count].name = name;
	context->names[context->name_count].ino  = (unsigned long)-1;
	context->names[context->name_count].rdev = -1;
	++context->name_count;
}

void audit_putname(const char *name)
{
	struct audit_context *context = current->audit_context;

	BUG_ON(!context);
	if (!context->in_syscall) {
		__putname(name);
	}
}

EXPORT_SYMBOL(audit_putname);

void audit_inode(const char *name, unsigned long ino, dev_t rdev)
{
	int idx;
	struct audit_context *context = current->audit_context;

	if (!context->in_syscall)
		return;
	if (context->name_count
	    && context->names[context->name_count-1].name
	    && context->names[context->name_count-1].name == name)
		idx = context->name_count - 1;
	else if (context->name_count > 1
		 && context->names[context->name_count-2].name
		 && context->names[context->name_count-2].name == name)
		idx = context->name_count - 2;
	else {
		/* FIXME: how much do we care about inodes that have no
		 * associated name? */
		if (context->name_count >= AUDIT_NAMES - AUDIT_NAMES_RESERVED)
			return;
		idx = context->name_count++;
		context->names[idx].name = NULL;
#if AUDIT_DEBUG
		++context->ino_count;
#endif
	}
	context->names[idx].ino  = ino;
	context->names[idx].rdev = rdev;
}



void audit_get_stamp(struct audit_context *ctx,
		     struct timespec *t, int *serial)
{
	if (ctx) {
		t->tv_sec  = ctx->ctime.tv_sec;
		t->tv_nsec = ctx->ctime.tv_nsec;
		*serial    = ctx->serial;
		ctx->auditable = 1;
	} else {
		*t      = CURRENT_TIME;
		*serial = 0;
	}
}