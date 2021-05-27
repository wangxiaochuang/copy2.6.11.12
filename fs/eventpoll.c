#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/smp_lock.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <linux/eventpoll.h>
#include <linux/mount.h>
#include <linux/bitops.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/mman.h>
#include <asm/atomic.h>
#include <asm/semaphore.h>

#define EVENTPOLLFS_MAGIC 0x03111965 /* My birthday should work for this :) */

#define DEBUG_EPOLL 0

#if DEBUG_EPOLL > 0
#define DPRINTK(x) printk x
#define DNPRINTK(n, x) do { if ((n) <= DEBUG_EPOLL) printk x; } while (0)
#else /* #if DEBUG_EPOLL > 0 */
#define DPRINTK(x) (void) 0
#define DNPRINTK(n, x) (void) 0
#endif /* #if DEBUG_EPOLL > 0 */

#define DEBUG_EPI 0

#if DEBUG_EPI != 0
#define EPI_SLAB_DEBUG (SLAB_DEBUG_FREE | SLAB_RED_ZONE /* | SLAB_POISON */)
#else /* #if DEBUG_EPI != 0 */
#define EPI_SLAB_DEBUG 0
#endif /* #if DEBUG_EPI != 0 */

/* Epoll private bits inside the event mask */
#define EP_PRIVATE_BITS (EPOLLONESHOT | EPOLLET)

/* Maximum number of poll wake up nests we are allowing */
#define EP_MAX_POLLWAKE_NESTS 4

/* Macro to allocate a "struct epitem" from the slab cache */
#define EPI_MEM_ALLOC()	(struct epitem *) kmem_cache_alloc(epi_cache, SLAB_KERNEL)

/* Macro to free a "struct epitem" to the slab cache */
#define EPI_MEM_FREE(p) kmem_cache_free(epi_cache, p)

/* Macro to allocate a "struct eppoll_entry" from the slab cache */
#define PWQ_MEM_ALLOC()	(struct eppoll_entry *) kmem_cache_alloc(pwq_cache, SLAB_KERNEL)

/* Macro to free a "struct eppoll_entry" to the slab cache */
#define PWQ_MEM_FREE(p) kmem_cache_free(pwq_cache, p)

/* Fast test to see if the file is an evenpoll file */
#define IS_FILE_EPOLL(f) ((f)->f_op == &eventpoll_fops)

/* Setup the structure that is used as key for the rb-tree */
#define EP_SET_FFD(p, f, d) do { (p)->file = (f); (p)->fd = (d); } while (0)

/* Compare rb-tree keys */
#define EP_CMP_FFD(p1, p2) ((p1)->file > (p2)->file ? +1: \
			    ((p1)->file < (p2)->file ? -1: (p1)->fd - (p2)->fd))

/* Special initialization for the rb-tree node to detect linkage */
#define EP_RB_INITNODE(n) (n)->rb_parent = (n)

/* Removes a node from the rb-tree and marks it for a fast is-linked check */
#define EP_RB_ERASE(n, r) do { rb_erase(n, r); (n)->rb_parent = (n); } while (0)

/* Fast check to verify that the item is linked to the main rb-tree */
#define EP_RB_LINKED(n) ((n)->rb_parent != (n))

/*
 * Remove the item from the list and perform its initialization.
 * This is useful for us because we can test if the item is linked
 * using "EP_IS_LINKED(p)".
 */
#define EP_LIST_DEL(p) do { list_del(p); INIT_LIST_HEAD(p); } while (0)

/* Tells us if the item is currently linked */
#define EP_IS_LINKED(p) (!list_empty(p))

/* Get the "struct epitem" from a wait queue pointer */
#define EP_ITEM_FROM_WAIT(p) ((struct epitem *) container_of(p, struct eppoll_entry, wait)->base)

/* Get the "struct epitem" from an epoll queue wrapper */
#define EP_ITEM_FROM_EPQUEUE(p) (container_of(p, struct ep_pqueue, pt)->epi)

/* Tells if the epoll_ctl(2) operation needs an event copy from userspace */
#define EP_OP_HASH_EVENT(op) ((op) != EPOLL_CTL_DEL)


struct epoll_filefd {
	struct file *file;
	int fd;
};

/*
 * Node that is linked into the "wake_task_list" member of the "struct poll_safewake".
 * It is used to keep track on all tasks that are currently inside the wake_up() code
 * to 1) short-circuit the one coming from the same task and same wait queue head
 * ( loop ) 2) allow a maximum number of epoll descriptors inclusion nesting
 * 3) let go the ones coming from other tasks.
 */
struct wake_task_node {
	struct list_head llink;
	task_t *task;
	wait_queue_head_t *wq;
};

/*
 * This is used to implement the safe poll wake up avoiding to reenter
 * the poll callback from inside wake_up().
 */
struct poll_safewake {
	struct list_head wake_task_list;
	spinlock_t lock;
};

/*
 * This structure is stored inside the "private_data" member of the file
 * structure and rapresent the main data sructure for the eventpoll
 * interface.
 */
struct eventpoll {
	/* Protect the this structure access */
	rwlock_t lock;

	/*
	 * This semaphore is used to ensure that files are not removed
	 * while epoll is using them. This is read-held during the event
	 * collection loop and it is write-held during the file cleanup
	 * path, the epoll file exit code and the ctl operations.
	 */
	struct rw_semaphore sem;

	/* Wait queue used by sys_epoll_wait() */
	wait_queue_head_t wq;

	/* Wait queue used by file->poll() */
	wait_queue_head_t poll_wait;

	/* List of ready file descriptors */
	struct list_head rdllist;

	/* RB-Tree root used to store monitored fd structs */
	struct rb_root rbr;
};

/* Wait structure used by the poll hooks */
struct eppoll_entry {
	/* List header used to link this structure to the "struct epitem" */
	struct list_head llink;

	/* The "base" pointer is set to the container "struct epitem" */
	void *base;

	/*
	 * Wait queue item that will be linked to the target file wait
	 * queue head.
	 */
	wait_queue_t wait;

	/* The wait queue head that linked the "wait" wait queue item */
	wait_queue_head_t *whead;
};

/*
 * Each file descriptor added to the eventpoll interface will
 * have an entry of this type linked to the hash.
 */
struct epitem {
	/* RB-Tree node used to link this structure to the eventpoll rb-tree */
	struct rb_node rbn;

	/* List header used to link this structure to the eventpoll ready list */
	struct list_head rdllink;

	/* The file descriptor information this item refers to */
	struct epoll_filefd ffd;

	/* Number of active wait queue attached to poll operations */
	int nwait;

	/* List containing poll wait queues */
	struct list_head pwqlist;

	/* The "container" of this item */
	struct eventpoll *ep;

	/* The structure that describe the interested events and the source fd */
	struct epoll_event event;

	/*
	 * Used to keep track of the usage count of the structure. This avoids
	 * that the structure will desappear from underneath our processing.
	 */
	atomic_t usecnt;

	/* List header used to link this item to the "struct file" items list */
	struct list_head fllink;

	/* List header used to link the item to the transfer list */
	struct list_head txlink;

	/*
	 * This is used during the collection/transfer of events to userspace
	 * to pin items empty events set.
	 */
	unsigned int revents;
};

/* Wrapper struct used by poll queueing */
struct ep_pqueue {
	poll_table pt;
	struct epitem *epi;
};



static void ep_poll_safewake_init(struct poll_safewake *psw);
static void ep_poll_safewake(struct poll_safewake *psw, wait_queue_head_t *wq);
static int ep_getfd(int *efd, struct inode **einode, struct file **efile);
static int ep_file_init(struct file *file);
static void ep_free(struct eventpoll *ep);
static struct epitem *ep_find(struct eventpoll *ep, struct file *file, int fd);
static void ep_use_epitem(struct epitem *epi);
static void ep_release_epitem(struct epitem *epi);
static void ep_ptable_queue_proc(struct file *file, wait_queue_head_t *whead,
				 poll_table *pt);
static void ep_rbtree_insert(struct eventpoll *ep, struct epitem *epi);
static int ep_insert(struct eventpoll *ep, struct epoll_event *event,
		     struct file *tfile, int fd);
static int ep_modify(struct eventpoll *ep, struct epitem *epi,
		     struct epoll_event *event);
static void ep_unregister_pollwait(struct eventpoll *ep, struct epitem *epi);
static int ep_unlink(struct eventpoll *ep, struct epitem *epi);
static int ep_remove(struct eventpoll *ep, struct epitem *epi);
static int ep_poll_callback(wait_queue_t *wait, unsigned mode, int sync, void *key);
static int ep_eventpoll_close(struct inode *inode, struct file *file);
static unsigned int ep_eventpoll_poll(struct file *file, poll_table *wait);
static int ep_collect_ready_items(struct eventpoll *ep,
				  struct list_head *txlist, int maxevents);
static int ep_send_events(struct eventpoll *ep, struct list_head *txlist,
			  struct epoll_event __user *events);
static void ep_reinject_items(struct eventpoll *ep, struct list_head *txlist);
static int ep_events_transfer(struct eventpoll *ep,
			      struct epoll_event __user *events,
			      int maxevents);
static int ep_poll(struct eventpoll *ep, struct epoll_event __user *events,
		   int maxevents, long timeout);
static int eventpollfs_delete_dentry(struct dentry *dentry);
static struct inode *ep_eventpoll_inode(void);
static struct super_block *eventpollfs_get_sb(struct file_system_type *fs_type,
					      int flags, const char *dev_name,
					      void *data);

/*
 * This semaphore is used to serialize ep_free() and eventpoll_release_file().
 */
struct semaphore epsem;

/* Safe wake up implementation */
static struct poll_safewake psw;

/* Slab cache used to allocate "struct epitem" */
static kmem_cache_t *epi_cache;

/* Slab cache used to allocate "struct eppoll_entry" */
static kmem_cache_t *pwq_cache;

/* Virtual fs used to allocate inodes for eventpoll files */
static struct vfsmount *eventpoll_mnt;

void eventpoll_init_file(struct file *file)
{
	INIT_LIST_HEAD(&file->f_ep_links);
	spin_lock_init(&file->f_ep_lock);
}

void eventpoll_release_file(struct file *file)
{
    struct list_head *lsthead = &file->f_ep_links;
	struct eventpoll *ep;
	struct epitem *epi;

    down(&epsem);
    while (!list_empty(lsthead)) {
        panic("in eventpoll_release_file function");
    }
    up(&epsem);
}