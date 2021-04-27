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