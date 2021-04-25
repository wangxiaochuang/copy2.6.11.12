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
    for(;;);
}
