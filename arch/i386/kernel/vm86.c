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



/* ---------------- vm86 special IRQ passing stuff ----------------- */

#define VM86_IRQNAME		"vm86irq"

static struct vm86_irqs {
	struct task_struct *tsk;
	int sig;
} vm86_irqs[16];

static DEFINE_SPINLOCK(irqbits_lock);
static int irqbits;

#define ALLOWED_SIGS ( 1 /* 0 = don't send a signal */ \
	| (1 << SIGUSR1) | (1 << SIGUSR2) | (1 << SIGIO)  | (1 << SIGURG) \
	| (1 << SIGUNUSED) )
	
static irqreturn_t irq_handler(int intno, void *dev_id, struct pt_regs * regs)
{
	int irq_bit;
	unsigned long flags;

	spin_lock_irqsave(&irqbits_lock, flags);	
	irq_bit = 1 << intno;
	if ((irqbits & irq_bit) || ! vm86_irqs[intno].tsk)
		goto out;
	irqbits |= irq_bit;
	if (vm86_irqs[intno].sig)
		send_sig(vm86_irqs[intno].sig, vm86_irqs[intno].tsk, 1);
	spin_unlock_irqrestore(&irqbits_lock, flags);
	/*
	 * IRQ will be re-enabled when user asks for the irq (whether
	 * polling or as a result of the signal)
	 */
	disable_irq(intno);
	return IRQ_HANDLED;

out:
	spin_unlock_irqrestore(&irqbits_lock, flags);	
	return IRQ_NONE;
}

static inline void free_vm86_irq(int irqnumber)
{
	unsigned long flags;

	free_irq(irqnumber, NULL);
	vm86_irqs[irqnumber].tsk = NULL;

	spin_lock_irqsave(&irqbits_lock, flags);	
	irqbits &= ~(1 << irqnumber);
	spin_unlock_irqrestore(&irqbits_lock, flags);	
}

void release_vm86_irqs(struct task_struct *task)
{
	int i;
	for (i = FIRST_VM86_IRQ ; i <= LAST_VM86_IRQ; i++)
	    if (vm86_irqs[i].tsk == task)
		free_vm86_irq(i);
}