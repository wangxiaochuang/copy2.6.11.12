#include <linux/module.h>
#include <linux/timex.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/fs.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

long pps_offset;		/* pps time offset (us) */
long pps_jitter = MAXTIME;	/* time dispersion (jitter) (us) */

long pps_freq;			/* frequency offset (scaled ppm) */
long pps_stabil = MAXFREQ;	/* frequency dispersion (scaled ppm) */

long pps_valid = PPS_VALID;	/* pps signal watchdog counter */

int pps_shift = PPS_SHIFT;	/* interval duration (s) (shift) */

long pps_jitcnt;		/* jitter limit exceeded */
long pps_calcnt;		/* calibration intervals */
long pps_errcnt;		/* calibration errors */
long pps_stbcnt;		/* stability limit exceeded */

inline struct timespec current_kernel_time(void)
{
        struct timespec now;
        unsigned long seq;

	do {
		seq = read_seqbegin(&xtime_lock);
		
		now = xtime;
	} while (read_seqretry(&xtime_lock, seq));

	return now; 
}

EXPORT_SYMBOL(current_kernel_time);


struct timespec current_fs_time(struct super_block *sb)
{
	struct timespec now = current_kernel_time();
	return timespec_trunc(now, sb->s_time_gran);
}
EXPORT_SYMBOL(current_fs_time);

struct timespec timespec_trunc(struct timespec t, unsigned gran)
{
	/*
	 * Division is pretty slow so avoid it for common cases.
	 * Currently current_kernel_time() never returns better than
	 * jiffies resolution. Exploit that.
	 */
	if (gran <= jiffies_to_usecs(1) * 1000) {
		/* nothing */
	} else if (gran == 1000000000) {
		t.tv_nsec = 0;
	} else {
		t.tv_nsec -= t.tv_nsec % gran;
	}
	return t;
}
EXPORT_SYMBOL(timespec_trunc);

#ifdef CONFIG_TIME_INTERPOLATION
#error "CONFIG_TIME_INTERPOLATION"
#else
/*
 * Simulate gettimeofday using do_gettimeofday which only allows a timeval
 * and therefore only yields usec accuracy
 */
void getnstimeofday(struct timespec *tv)
{
	struct timeval x;

	do_gettimeofday(&x);
	tv->tv_sec = x.tv_sec;
	tv->tv_nsec = x.tv_usec * NSEC_PER_USEC;
}
#endif