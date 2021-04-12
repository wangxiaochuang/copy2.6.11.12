#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/kd.h>
#include <linux/slab.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/devfs_fs_kernel.h>
#include <linux/vt_kern.h>
#include <linux/selection.h>
#include <linux/tiocl.h>
#include <linux/kbd_kern.h>
#include <linux/consolemap.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/config.h>
#include <linux/workqueue.h>
#include <linux/bootmem.h>
#include <linux/pm.h>
#include <linux/font.h>
#include <linux/bitops.h>

#include <asm/io.h>
#include <asm/system.h>
#include <asm/uaccess.h>

#include "console_macros.h"


const struct consw *conswitchp;