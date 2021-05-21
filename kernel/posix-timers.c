#include <linux/mm.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/time.h>

#include <asm/uaccess.h>
#include <asm/semaphore.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/idr.h>
#include <linux/posix-timers.h>
#include <linux/syscalls.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

static inline void itimer_delete(struct k_itimer *timer)
{
	panic("in itimer_delete function");
}

void exit_itimers(struct signal_struct *sig)
{
	struct k_itimer *tmr;

	while (!list_empty(&sig->posix_timers)) {
		tmr = list_entry(sig->posix_timers.next, struct k_itimer, list);
		itimer_delete(tmr);
	}
}

/*
 * We do ticks here to avoid the irq lock ( they take sooo long).
 * The seqlock is great here.  Since we a reader, we don't really care
 * if we are interrupted since we don't take lock that will stall us or
 * any other cpu. Voila, no irq lock is needed.
 *
 */

static u64 do_posix_clock_monotonic_gettime_parts(
	struct timespec *tp, struct timespec *mo)
{
	u64 jiff;
	unsigned int seq;

	do {
		seq = read_seqbegin(&xtime_lock);
		getnstimeofday(tp);
		*mo = wall_to_monotonic;
		jiff = jiffies_64;

	} while(read_seqretry(&xtime_lock, seq));

	return jiff;
}

int do_posix_clock_monotonic_gettime(struct timespec *tp)
{
	struct timespec wall_to_mono;

	do_posix_clock_monotonic_gettime_parts(tp, &wall_to_mono);

	tp->tv_sec += wall_to_mono.tv_sec;
	tp->tv_nsec += wall_to_mono.tv_nsec;

	if ((tp->tv_nsec - NSEC_PER_SEC) > 0) {
		tp->tv_nsec -= NSEC_PER_SEC;
		tp->tv_sec++;
	}
	return 0;
}

void clock_was_set(void) {

}