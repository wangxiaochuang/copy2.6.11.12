#include <linux/init.h>
#include <asm/atomic.h>
#include <asm/types.h>
#include <linux/mm.h>
#include <linux/module.h>

#include <linux/audit.h>

#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>

/* No auditing will take place until audit_initialized != 0.
 * (Initialization happens after skb_init is called.) */
static int	audit_initialized;

/* No syscall auditing will take place unless audit_enabled != 0. */
int		audit_enabled;

/* Default state when kernel boots without any parameters. */
static int	audit_default;

/* If auditing cannot proceed, audit_failure selects what happens. */
static int	audit_failure = AUDIT_FAIL_PRINTK;

/* If audit records are to be written to the netlink socket, audit_pid
 * contains the (non-zero) pid. */
static int	audit_pid;

/* If audit_limit is non-zero, limit the rate of sending audit records
 * to that number per second.  This prevents DoS attacks, but results in
 * audit records being dropped. */
static int	audit_rate_limit;

/* Number of outstanding audit_buffers allowed. */
static int	audit_backlog_limit = 64;
static atomic_t	audit_backlog	    = ATOMIC_INIT(0);

/* Records can be lost in several ways:
   0) [suppressed in audit_alloc]
   1) out of memory in audit_log_start [kmalloc of struct audit_buffer]
   2) out of memory in audit_log_move [alloc_skb]
   3) suppressed due to audit_rate_limit
   4) suppressed due to audit_backlog_limit
*/
static atomic_t    audit_lost = ATOMIC_INIT(0);

/* The netlink socket. */
static struct sock *audit_sock;

/* There are two lists of audit buffers.  The txlist contains audit
 * buffers that cannot be sent immediately to the netlink device because
 * we are in an irq context (these are sent later in a tasklet).
 *
 * The second list is a list of pre-allocated audit buffers (if more
 * than AUDIT_MAXFREE are in use, the audit buffer is freed instead of
 * being placed on the freelist). */
static DEFINE_SPINLOCK(audit_txlist_lock);
static DEFINE_SPINLOCK(audit_freelist_lock);
static int	   audit_freelist_count = 0;
static LIST_HEAD(audit_txlist);
static LIST_HEAD(audit_freelist);

/* There are three lists of rules -- one to search at task creation
 * time, one to search at syscall entry time, and another to search at
 * syscall exit time. */
static LIST_HEAD(audit_tsklist);
static LIST_HEAD(audit_entlist);
static LIST_HEAD(audit_extlist);

/* The netlink socket is only to be read by 1 CPU, which lets us assume
 * that list additions and deletions never happen simultaneiously in
 * auditsc.c */
static DECLARE_MUTEX(audit_netlink_sem);

/* AUDIT_BUFSIZ is the size of the temporary buffer used for formatting
 * audit records.  Since printk uses a 1024 byte buffer, this buffer
 * should be at least that large. */
#define AUDIT_BUFSIZ 1024

/* AUDIT_MAXFREE is the number of empty audit_buffers we keep on the
 * audit_freelist.  Doing so eliminates many kmalloc/kfree calls. */
#define AUDIT_MAXFREE  (2*NR_CPUS)

/* The audit_buffer is used when formatting an audit record.  The caller
 * locks briefly to get the record off the freelist or to allocate the
 * buffer, and locks briefly to send the buffer to the netlink layer or
 * to place it on a transmit queue.  Multiple audit_buffers can be in
 * use simultaneously. */
struct audit_buffer {
	struct list_head     list;
	struct sk_buff_head  sklist;	/* formatted skbs ready to send */
	struct audit_context *ctx;	/* NULL or associated context */
	int		     len;	/* used area of tmp */
	char		     tmp[AUDIT_BUFSIZ];

				/* Pointer to header and contents */
	struct nlmsghdr      *nlh;
	int		     total;
	int		     type;
	int		     pid;
	int		     count; /* Times requeued */
};

void audit_set_type(struct audit_buffer *ab, int type)
{
	ab->type = type;
}

struct audit_entry {
	struct list_head  list;
	struct audit_rule rule;
};

static void audit_panic(const char *message)
{
	switch (audit_failure)
	{
	case AUDIT_FAIL_SILENT:
		break;
	case AUDIT_FAIL_PRINTK:
		printk(KERN_ERR "audit: %s\n", message);
		break;
	case AUDIT_FAIL_PANIC:
		panic("audit: %s\n", message);
		break;
	}
}


static inline int audit_rate_check(void)
{
	static unsigned long	last_check = 0;
	static int		messages   = 0;
	static DEFINE_SPINLOCK(lock);
	unsigned long		flags;
	unsigned long		now;
	unsigned long		elapsed;
	int			retval	   = 0;

	if (!audit_rate_limit) return 1;

	spin_lock_irqsave(&lock, flags);
	if (++messages < audit_rate_limit) {
		retval = 1;
	} else {
		now     = jiffies;
		elapsed = now - last_check;
		if (elapsed > HZ) {
			last_check = now;
			messages   = 0;
			retval     = 1;
		}
	}
	spin_unlock_irqrestore(&lock, flags);

	return retval;
}

/* Emit at least 1 message per second, even if audit_rate_check is
 * throttling. */
void audit_log_lost(const char *message)
{
	static unsigned long	last_msg = 0;
	static DEFINE_SPINLOCK(lock);
	unsigned long		flags;
	unsigned long		now;
	int			print;

	atomic_inc(&audit_lost);

	print = (audit_failure == AUDIT_FAIL_PANIC || !audit_rate_limit);

	if (!print) {
		spin_lock_irqsave(&lock, flags);
		now = jiffies;
		if (now - last_msg > HZ) {
			print = 1;
			last_msg = now;
		}
		spin_unlock_irqrestore(&lock, flags);
	}

	if (print) {
		printk(KERN_WARNING
		       "audit: audit_lost=%d audit_backlog=%d"
		       " audit_rate_limit=%d audit_backlog_limit=%d\n",
		       atomic_read(&audit_lost),
		       atomic_read(&audit_backlog),
		       audit_rate_limit,
		       audit_backlog_limit);
		audit_panic(message);
	}

}



int audit_set_rate_limit(int limit)
{
	int old		 = audit_rate_limit;
	audit_rate_limit = limit;
	audit_log(current->audit_context, "audit_rate_limit=%d old=%d",
		  audit_rate_limit, old);
	return old;
}

static void audit_log_move(struct audit_buffer *ab)
{
	panic("in audit_log_move");
}

static inline int audit_log_drain(struct audit_buffer *ab)
{
	panic("in audit_log_drain function");
	return 0;
}

struct audit_buffer *audit_log_start(struct audit_context *ctx)
{
	struct audit_buffer	*ab	= NULL;
	unsigned long		flags;
	struct timespec		t;
	int			serial	= 0;

	if (!audit_initialized)
		return NULL;

	if (audit_backlog_limit
	    && atomic_read(&audit_backlog) > audit_backlog_limit) {
		if (audit_rate_check())
			printk(KERN_WARNING
			       "audit: audit_backlog=%d > "
			       "audit_backlog_limit=%d\n",
			       atomic_read(&audit_backlog),
			       audit_backlog_limit);
		audit_log_lost("backlog limit exceeded");
		return NULL;
	}

	spin_lock_irqsave(&audit_freelist_lock, flags);
	if (!list_empty(&audit_freelist)) {
		ab = list_entry(audit_freelist.next,
				struct audit_buffer, list);
		list_del(&ab->list);
		--audit_freelist_count;
	}
	spin_unlock_irqrestore(&audit_freelist_lock, flags);

	if (!ab)
		ab = kmalloc(sizeof(*ab), GFP_ATOMIC);
	if (!ab) {
		audit_log_lost("out of memory in audit_log_start");
		return NULL;
	}

	atomic_inc(&audit_backlog);
	skb_queue_head_init(&ab->sklist);

	ab->ctx   = ctx;
	ab->len   = 0;
	ab->nlh   = NULL;
	ab->total = 0;
	ab->type  = AUDIT_KERNEL;
	ab->pid   = 0;
	ab->count = 0;

#ifdef CONFIG_AUDITSYSCALL
	if (ab->ctx)
		audit_get_stamp(ab->ctx, &t, &serial);
	else
#endif
		t = CURRENT_TIME;

	audit_log_format(ab, "audit(%lu.%03lu:%u): ",
			 t.tv_sec, t.tv_nsec/1000000, serial);
	return ab;
}

static void audit_log_vformat(struct audit_buffer *ab, const char *fmt,
			      va_list args)
{
	int len, avail;

	if (!ab)
		return;

	avail = sizeof(ab->tmp) - ab->len;
	if (avail <= 0) {
		audit_log_move(ab);
		avail = sizeof(ab->tmp) - ab->len;
	}
	len   = vsnprintf(ab->tmp + ab->len, avail, fmt, args);
	if (len >= avail) {
		/* The printk buffer is 1024 bytes long, so if we get
		 * here and AUDIT_BUFSIZ is at least 1024, then we can
		 * log everything that printk could have logged. */
		audit_log_move(ab);
		avail = sizeof(ab->tmp) - ab->len;
		len   = vsnprintf(ab->tmp + ab->len, avail, fmt, args);
	}
	ab->len   += (len < avail) ? len : avail;
	ab->total += (len < avail) ? len : avail;
}

void audit_log_format(struct audit_buffer *ab, const char *fmt, ...)
{
	va_list args;

	if (!ab)
		return;
	va_start(args, fmt);
	audit_log_vformat(ab, fmt, args);
	va_end(args);
}

static void audit_tasklet_handler(unsigned long arg)
{
	LIST_HEAD(list);
	struct audit_buffer *ab;
	unsigned long	    flags;

	spin_lock_irqsave(&audit_txlist_lock, flags);
	list_splice_init(&audit_txlist, &list);
	spin_unlock_irqrestore(&audit_txlist_lock, flags);

	while (!list_empty(&list)) {
		ab = list_entry(list.next, struct audit_buffer, list);
		list_del(&ab->list);
		audit_log_end_fast(ab);
	}
}

static DECLARE_TASKLET(audit_tasklet, audit_tasklet_handler, 0);

void audit_log_end_irq(struct audit_buffer *ab)
{
	unsigned long flags;

	if (!ab)
		return;
	spin_lock_irqsave(&audit_txlist_lock, flags);
	list_add_tail(&ab->list, &audit_txlist);
	spin_unlock_irqrestore(&audit_txlist_lock, flags);

	tasklet_schedule(&audit_tasklet);
}

void audit_log_end_fast(struct audit_buffer *ab)
{
	unsigned long flags;

	BUG_ON(in_irq());
	if (!ab)
		return;
	if (!audit_rate_check()) {
		audit_log_lost("rate limit exceeded");
	} else {
		audit_log_move(ab);
		if (audit_log_drain(ab))
			return;
	}

	atomic_dec(&audit_backlog);
	spin_lock_irqsave(&audit_freelist_lock, flags);
	if (++audit_freelist_count > AUDIT_MAXFREE)
		kfree(ab);
	else
		list_add(&ab->list, &audit_freelist);
	spin_unlock_irqrestore(&audit_freelist_lock, flags);
}

void audit_log_end(struct audit_buffer *ab)
{
	if (in_irq())
		audit_log_end_irq(ab);
	else
		audit_log_end_fast(ab);
}

void audit_log(struct audit_context *ctx, const char *fmt, ...)
{
    printk("############ audit_log not implement\n");
}