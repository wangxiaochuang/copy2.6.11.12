#include <linux/config.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/utsname.h>
#include <linux/mman.h>
#include <linux/smp_lock.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/prctl.h>
#include <linux/init.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/device.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/security.h>
#include <linux/dcookies.h>
#include <linux/suspend.h>
#include <linux/tty.h>

#include <linux/compat.h>
#include <linux/syscalls.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>

struct group_info init_groups = { .usage = ATOMIC_INIT(2) };