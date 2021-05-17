#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>

/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
fastcall unsigned int do_IRQ(struct pt_regs *regs)
{
    int irq = regs->orig_eax & 0xff;
#ifdef CONFIG_4KSTACKS
#error "CONFIG_4KSTACKS"
#endif

    irq_enter();
#ifdef CONFIG_DEBUG_STACKOVERFLOW
#error "CONFIG_DEBUG_STACKOVERFLOW"
#endif

#ifdef CONFIG_4KSTACKS
#error "CONFIG_4KSTACKS"
#endif

    __do_IRQ(irq, regs);

    irq_exit();

    return 1;
}

/*
 * Interrupt statistics:
 */

atomic_t irq_err_count;

/*
 * /proc/interrupts printing:
 */

int show_interrupts(struct seq_file *p, void *v)
{
    return 0;
}