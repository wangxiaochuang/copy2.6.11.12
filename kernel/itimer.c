#include <linux/mm.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/syscalls.h>
#include <linux/time.h>

#include <asm/uaccess.h>

void it_real_fn(unsigned long __data) {
}