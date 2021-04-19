#include <linux/config.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/tlbflush.h>
#include <asm/irq.h>

struct pt_regs * FASTCALL(save_v86_state(struct kernel_vm86_regs * regs));
struct pt_regs * fastcall save_v86_state(struct kernel_vm86_regs * regs)
{
    return NULL;
}