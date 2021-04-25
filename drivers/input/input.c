#include <linux/init.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/input.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/major.h>
#include <linux/proc_fs.h>
#include <linux/kobject_uevent.h>
#include <linux/interrupt.h>
#include <linux/poll.h>
#include <linux/device.h>
#include <linux/devfs_fs_kernel.h>

void input_event(struct input_dev *dev, unsigned int type, unsigned int code, int value)
{
}