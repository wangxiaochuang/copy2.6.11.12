#include <linux/config.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/notifier.h>
#include <linux/init.h>
#include <linux/sysrq.h>
#include <linux/interrupt.h>
#include <linux/nmi.h>

int tainted;

NORET_TYPE void panic(const char * fmt, ...) {
    static char buf[1024];
	va_list args;

    va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
    printk("####panic#### %s", buf);
    for(;;);
}
