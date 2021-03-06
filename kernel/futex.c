#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/jhash.h>
#include <linux/init.h>
#include <linux/futex.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>

#define FUTEX_HASHBITS 8

union futex_key {
	struct {
		unsigned long pgoff;
		struct inode *inode;
		int offset;
	} shared;
	struct {
		unsigned long uaddr;
		struct mm_struct *mm;
		int offset;
	} private;
	struct {
		unsigned long word;
		void *ptr;
		int offset;
	} both;
};

/*
 * We use this hashed waitqueue instead of a normal wait_queue_t, so
 * we can wake only the relevant ones (hashed queues may be shared).
 *
 * A futex_q has a woken state, just like tasks have TASK_RUNNING.
 * It is considered woken when list_empty(&q->list) || q->lock_ptr == 0.
 * The order of wakup is always to make the first condition true, then
 * wake up q->waiters, then make the second condition true.
 */
struct futex_q {
	struct list_head list;
	wait_queue_head_t waiters;

	/* Which hash list lock to use. */
	spinlock_t *lock_ptr;

	/* Key which the futex is hashed on. */
	union futex_key key;

	/* For fd, sigio sent using these. */
	int fd;
	struct file *filp;
};

/*
 * Split the global futex_lock into every hash list lock.
 */
struct futex_hash_bucket {
       spinlock_t              lock;
       unsigned int	    nqueued;
       struct list_head       chain;
};

static struct futex_hash_bucket futex_queues[1<<FUTEX_HASHBITS];

/* Futex-fs vfsmount entry: */
static struct vfsmount *futex_mnt;

/*
 * We hash on the keys returned from get_futex_key (see below).
 */
static struct futex_hash_bucket *hash_futex(union futex_key *key)
{
	u32 hash = jhash2((u32*)&key->both.word,
			  (sizeof(key->both.word)+sizeof(key->both.ptr))/4,
			  key->both.offset);
	return &futex_queues[hash & ((1 << FUTEX_HASHBITS)-1)];
}

/*
 * Return 1 if two futex_keys are equal, 0 otherwise.
 */
static inline int match_futex(union futex_key *key1, union futex_key *key2)
{
	return (key1->both.word == key2->both.word
		&& key1->both.ptr == key2->both.ptr
		&& key1->both.offset == key2->both.offset);
}

static int get_futex_key(unsigned long uaddr, union futex_key *key)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct page *page;
	int err;

	/*
	 * The futex address must be "naturally" aligned.
	 */
	key->both.offset = uaddr % PAGE_SIZE;
	if (unlikely((key->both.offset % sizeof(u32)) != 0))
		return -EINVAL;
	uaddr -= key->both.offset;

	/*
	 * The futex is hashed differently depending on whether
	 * it's in a shared or private mapping.  So check vma first.
	 */
	vma = find_extend_vma(mm, uaddr);
	if (unlikely(!vma))
		return -EFAULT;

	/*
	 * Permissions.
	 */
	if (unlikely((vma->vm_flags & (VM_IO|VM_READ)) != VM_READ))
		return (vma->vm_flags & VM_IO) ? -EPERM : -EACCES;

	/*
	 * Private mappings are handled in a simple way.
	 *
	 * NOTE: When userspace waits on a MAP_SHARED mapping, even if
	 * it's a read-only handle, it's expected that futexes attach to
	 * the object not the particular process.  Therefore we use
	 * VM_MAYSHARE here, not VM_SHARED which is restricted to shared
	 * mappings of _writable_ handles.
	 */
	if (likely(!(vma->vm_flags & VM_MAYSHARE))) {
		key->private.mm = mm;
		key->private.uaddr = uaddr;
		return 0;
	}

	/*
	 * Linear file mappings are also simple.
	 */
	key->shared.inode = vma->vm_file->f_dentry->d_inode;
	key->both.offset++; /* Bit 0 of offset indicates inode-based key. */
	if (likely(!(vma->vm_flags & VM_NONLINEAR))) {
		key->shared.pgoff = (((uaddr - vma->vm_start) >> PAGE_SHIFT)
				     + vma->vm_pgoff);
		return 0;
	}

	/*
	 * We could walk the page table to read the non-linear
	 * pte, and get the page index without fetching the page
	 * from swap.  But that's a lot of code to duplicate here
	 * for a rare case, so we simply fetch the page.
	 */

	/*
	 * Do a quick atomic lookup first - this is the fastpath.
	 */
	spin_lock(&current->mm->page_table_lock);
	page = follow_page(mm, uaddr, 0);
	if (likely(page != NULL)) {
		key->shared.pgoff =
			page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
		spin_unlock(&current->mm->page_table_lock);
		return 0;
	}
	spin_unlock(&current->mm->page_table_lock);

	/*
	 * Do it the general way.
	 */
	err = get_user_pages(current, mm, uaddr, 1, 0, 0, &page, NULL);
	if (err >= 0) {
		key->shared.pgoff =
			page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
		put_page(page);
		return 0;
	}
	return err;
}

static inline void get_key_refs(union futex_key *key)
{
	if (key->both.ptr != 0) {
		if (key->both.offset & 1)
			atomic_inc(&key->shared.inode->i_count);
		else
			atomic_inc(&key->private.mm->mm_count);
	}
}

/*
 * Drop a reference to the resource addressed by a key.
 * The hash bucket spinlock must not be held.
 */
static void drop_key_refs(union futex_key *key)
{
	if (key->both.ptr != 0) {
		if (key->both.offset & 1)
			iput(key->shared.inode);
		else
			mmdrop(key->private.mm);
	}
}

static inline int get_futex_value_locked(int *dest, int __user *from)
{
	int ret;

	inc_preempt_count();
	ret = __copy_from_user_inatomic(dest, from, sizeof(int));
	dec_preempt_count();
	preempt_check_resched();

	return ret ? -EFAULT : 0;
}

static void wake_futex(struct futex_q *q)
{
	list_del_init(&q->list);
	if (q->filp)
		send_sigio(&q->filp->f_owner, q->fd, POLL_IN);
	/*
	 * The lock in wake_up_all() is a crucial memory barrier after the
	 * list_del_init() and also before assigning to q->lock_ptr.
	 */
	wake_up_all(&q->waiters);
	/*
	 * The waiting task can free the futex_q as soon as this is written,
	 * without taking any locks.  This must come last.
	 */
	q->lock_ptr = NULL;
}

static int futex_wake(unsigned long uaddr, int nr_wake)
{
	union futex_key key;
	struct futex_hash_bucket *bh;
	struct list_head *head;
	struct futex_q *this, *next;
	int ret;

	down_read(&current->mm->mmap_sem);

	ret = get_futex_key(uaddr, &key);
	if (unlikely(ret != 0))
		goto out;

	bh = hash_futex(&key);
	spin_lock(&bh->lock);
	head = &bh->chain;

	list_for_each_entry_safe(this, next, head, list) {
		if (match_futex (&this->key, &key)) {
			wake_futex(this);
			if (++ret >= nr_wake)
				break;
		}
	}

	spin_unlock(&bh->lock);
out:
	up_read(&current->mm->mmap_sem);
	return ret;
}

static int futex_requeue(unsigned long uaddr1, unsigned long uaddr2,
			 int nr_wake, int nr_requeue, int *valp)
{
	union futex_key key1, key2;
	struct futex_hash_bucket *bh1, *bh2;
	struct list_head *head1;
	struct futex_q *this, *next;
	int ret, drop_count = 0;
	unsigned int nqueued;

 retry:
	down_read(&current->mm->mmap_sem);

	ret = get_futex_key(uaddr1, &key1);
	if (unlikely(ret != 0))
		goto out;
	ret = get_futex_key(uaddr2, &key2);
	if (unlikely(ret != 0))
		goto out;

	bh1 = hash_futex(&key1);
	bh2 = hash_futex(&key2);

	nqueued = bh1->nqueued;
	if (likely(valp != NULL)) {
		int curval;

		/* In order to avoid doing get_user while
		   holding bh1->lock and bh2->lock, nqueued
		   (monotonically increasing field) must be first
		   read, then *uaddr1 fetched from userland and
		   after acquiring lock nqueued field compared with
		   the stored value.  The smp_mb () below
		   makes sure that bh1->nqueued is read from memory
		   before *uaddr1.  */
		smp_mb();

		ret = get_futex_value_locked(&curval, (int __user *)uaddr1);

		if (unlikely(ret)) {
			/* If we would have faulted, release mmap_sem, fault
			 * it in and start all over again.
			 */
			up_read(&current->mm->mmap_sem);

			ret = get_user(curval, (int __user *)uaddr1);

			if (!ret)
				goto retry;

			return ret;
		}
		if (curval != *valp) {
			ret = -EAGAIN;
			goto out;
		}
	}

	if (bh1 < bh2)
		spin_lock(&bh1->lock);
	spin_lock(&bh2->lock);
	if (bh1 > bh2)
		spin_lock(&bh1->lock);

	if (unlikely(nqueued != bh1->nqueued && valp != NULL)) {
		ret = -EAGAIN;
		goto out_unlock;
	}

	head1 = &bh1->chain;
	list_for_each_entry_safe(this, next, head1, list) {
		if (!match_futex (&this->key, &key1))
			continue;
		if (++ret <= nr_wake) {
			wake_futex(this);
		} else {
			list_move_tail(&this->list, &bh2->chain);
			this->lock_ptr = &bh2->lock;
			this->key = key2;
			get_key_refs(&key2);
			drop_count++;

			if (ret - nr_wake >= nr_requeue)
				break;
			/* Make sure to stop if key1 == key2 */
			if (head1 == &bh2->chain && head1 != &next->list)
				head1 = &this->list;
		}
	}

out_unlock:
	spin_unlock(&bh1->lock);
	if (bh1 != bh2)
		spin_unlock(&bh2->lock);

	/* drop_key_refs() must be called outside the spinlocks. */
	while (--drop_count >= 0)
		drop_key_refs(&key1);

out:
	up_read(&current->mm->mmap_sem);
	return ret;
}

static void queue_me(struct futex_q *q, int fd, struct file *filp)
{
	struct futex_hash_bucket *bh;

	q->fd = fd;
	q->filp = filp;

	init_waitqueue_head(&q->waiters);

	get_key_refs(&q->key);
	bh = hash_futex(&q->key);
	q->lock_ptr = &bh->lock;

	spin_lock(&bh->lock);
	bh->nqueued++;
	list_add_tail(&q->list, &bh->chain);
	spin_unlock(&bh->lock);
}

static int unqueue_me(struct futex_q *q)
{
	int ret = 0;
	spinlock_t *lock_ptr;

	/* In the common case we don't take the spinlock, which is nice. */
 retry:
	lock_ptr = q->lock_ptr;
	if (lock_ptr != 0) {
		spin_lock(lock_ptr);
		/*
		 * q->lock_ptr can change between reading it and
		 * spin_lock(), causing us to take the wrong lock.  This
		 * corrects the race condition.
		 *
		 * Reasoning goes like this: if we have the wrong lock,
		 * q->lock_ptr must have changed (maybe several times)
		 * between reading it and the spin_lock().  It can
		 * change again after the spin_lock() but only if it was
		 * already changed before the spin_lock().  It cannot,
		 * however, change back to the original value.  Therefore
		 * we can detect whether we acquired the correct lock.
		 */
		if (unlikely(lock_ptr != q->lock_ptr)) {
			spin_unlock(lock_ptr);
			goto retry;
		}
		WARN_ON(list_empty(&q->list));
		list_del(&q->list);
		spin_unlock(lock_ptr);
		ret = 1;
	}

	drop_key_refs(&q->key);
	return ret;
}

static int futex_wait(unsigned long uaddr, int val, unsigned long time)
{
	DECLARE_WAITQUEUE(wait, current);
	int ret, curval;
	struct futex_q q;

 retry:
	down_read(&current->mm->mmap_sem);

	ret = get_futex_key(uaddr, &q.key);
	if (unlikely(ret != 0))
		goto out_release_sem;

	queue_me(&q, -1, NULL);

	/*
	 * Access the page AFTER the futex is queued.
	 * Order is important:
	 *
	 *   Userspace waiter: val = var; if (cond(val)) futex_wait(&var, val);
	 *   Userspace waker:  if (cond(var)) { var = new; futex_wake(&var); }
	 *
	 * The basic logical guarantee of a futex is that it blocks ONLY
	 * if cond(var) is known to be true at the time of blocking, for
	 * any cond.  If we queued after testing *uaddr, that would open
	 * a race condition where we could block indefinitely with
	 * cond(var) false, which would violate the guarantee.
	 *
	 * A consequence is that futex_wait() can return zero and absorb
	 * a wakeup when *uaddr != val on entry to the syscall.  This is
	 * rare, but normal.
	 *
	 * We hold the mmap semaphore, so the mapping cannot have changed
	 * since we looked it up in get_futex_key.
	 */

	ret = get_futex_value_locked(&curval, (int __user *)uaddr);

	if (unlikely(ret)) {
		/* If we would have faulted, release mmap_sem, fault it in and
		 * start all over again.
		 */
		up_read(&current->mm->mmap_sem);

		if (!unqueue_me(&q)) /* There's a chance we got woken already */
			return 0;

		ret = get_user(curval, (int __user *)uaddr);

		if (!ret)
			goto retry;
		return ret;
	}
	if (curval != val) {
		ret = -EWOULDBLOCK;
		goto out_unqueue;
	}

	/*
	 * Now the futex is queued and we have checked the data, we
	 * don't want to hold mmap_sem while we sleep.
	 */	
	up_read(&current->mm->mmap_sem);

	/*
	 * There might have been scheduling since the queue_me(), as we
	 * cannot hold a spinlock across the get_user() in case it
	 * faults, and we cannot just set TASK_INTERRUPTIBLE state when
	 * queueing ourselves into the futex hash.  This code thus has to
	 * rely on the futex_wake() code removing us from hash when it
	 * wakes us up.
	 */

	/* add_wait_queue is the barrier after __set_current_state. */
	__set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&q.waiters, &wait);
	/*
	 * !list_empty() is safe here without any lock.
	 * q.lock_ptr != 0 is not safe, because of ordering against wakeup.
	 */
	if (likely(!list_empty(&q.list)))
		time = schedule_timeout(time);
	__set_current_state(TASK_RUNNING);

	/*
	 * NOTE: we don't remove ourselves from the waitqueue because
	 * we are the only user of it.
	 */

	/* If we were woken (and unqueued), we succeeded, whatever. */
	if (!unqueue_me(&q))
		return 0;
	if (time == 0)
		return -ETIMEDOUT;
	/* We expect signal_pending(current), but another thread may
	 * have handled it for us already. */
	return -EINTR;

 out_unqueue:
	/* If we were woken (and unqueued), we succeeded, whatever. */
	if (!unqueue_me(&q))
		ret = 0;
 out_release_sem:
	up_read(&current->mm->mmap_sem);
	return ret;
}

static int futex_close(struct inode *inode, struct file *filp)
{
	struct futex_q *q = filp->private_data;

	unqueue_me(q);
	kfree(q);
	return 0;
}

static unsigned int futex_poll(struct file *filp,
			       struct poll_table_struct *wait)
{
    return 0;
}

static struct file_operations futex_fops = {
	.release	= futex_close,
	.poll		= futex_poll,
};

static int futex_fd(unsigned long uaddr, int signal)
{
	struct futex_q *q;
	struct file *filp;
	int ret, err;

	ret = -EINVAL;
	if (signal < 0 || signal > _NSIG)
		goto out;

	ret = get_unused_fd();
	if (ret < 0)
		goto out;
	filp = get_empty_filp();
	if (!filp) {
		put_unused_fd(ret);
		ret = -ENFILE;
		goto out;
	}
	filp->f_op = &futex_fops;
	filp->f_vfsmnt = mntget(futex_mnt);
	filp->f_dentry = dget(futex_mnt->mnt_root);
	filp->f_mapping = filp->f_dentry->d_inode->i_mapping;

	if (signal) {
		int err;
		err = f_setown(filp, current->pid, 1);
		if (err < 0) {
			put_unused_fd(ret);
			put_filp(filp);
			ret = err;
			goto out;
		}
		filp->f_owner.signum = signal;
	}

	q = kmalloc(sizeof(*q), GFP_KERNEL);
	if (!q) {
		put_unused_fd(ret);
		put_filp(filp);
		ret = -ENOMEM;
		goto out;
	}

	down_read(&current->mm->mmap_sem);
	err = get_futex_key(uaddr, &q->key);

	if (unlikely(err != 0)) {
		up_read(&current->mm->mmap_sem);
		put_unused_fd(ret);
		put_filp(filp);
		kfree(q);
		return err;
	}

	/*
	 * queue_me() must be called before releasing mmap_sem, because
	 * key->shared.inode needs to be referenced while holding it.
	 */
	filp->private_data = q;

	queue_me(q, ret, filp);
	up_read(&current->mm->mmap_sem);

	/* Now we map fd to filp, so userspace can access it */
	fd_install(ret, filp);
out:
	return ret;
}

long do_futex(unsigned long uaddr, int op, int val, unsigned long timeout,
		unsigned long uaddr2, int val2, int val3)
{
	int ret;

	switch (op) {
	case FUTEX_WAIT:
		ret = futex_wait(uaddr, val, timeout);
		break;
	case FUTEX_WAKE:
		ret = futex_wake(uaddr, val);
		break;
	case FUTEX_FD:
		/* non-zero val means F_SETOWN(getpid()) & F_SETSIG(val) */
		ret = futex_fd(uaddr, val);
		break;
	case FUTEX_REQUEUE:
		ret = futex_requeue(uaddr, uaddr2, val, val2, NULL);
		break;
	case FUTEX_CMP_REQUEUE:
		ret = futex_requeue(uaddr, uaddr2, val, val2, &val3);
		break;
	default:
		ret = -ENOSYS;
	}
	return ret;
}

asmlinkage long sys_futex(u32 __user *uaddr, int op, int val,
			  struct timespec __user *utime, u32 __user *uaddr2,
			  int val3)
{
	struct timespec t;
	unsigned long timeout = MAX_SCHEDULE_TIMEOUT;
	int val2 = 0;

	if ((op == FUTEX_WAIT) && utime) {
		if (copy_from_user(&t, utime, sizeof(t)) != 0)
			return -EFAULT;
		timeout = timespec_to_jiffies(&t) + 1;
	}
	/*
	 * requeue parameter in 'utime' if op == FUTEX_REQUEUE.
	 */
	if (op >= FUTEX_REQUEUE)
		val2 = (int) (unsigned long) utime;

	return do_futex((unsigned long)uaddr, op, val, timeout,
			(unsigned long)uaddr2, val2, val3);
}