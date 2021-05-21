#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/ldt.h>
#include <asm/desc.h>

#ifdef CONFIG_SMP /* avoids "defined but not used" warnig */
static void flush_ldt(void *null)
{
	if (current->active_mm)
		load_LDT(&current->active_mm->context);
}
#endif

static int alloc_ldt(mm_context_t *pc, int mincount, int reload)
{
	void *oldldt;
	void *newldt;
	int oldsize;

	if (mincount <= pc->size)
		return 0;
	oldsize = pc->size;
    mincount = (mincount+511)&(~511);
	if (mincount*LDT_ENTRY_SIZE > PAGE_SIZE)
		newldt = vmalloc(mincount*LDT_ENTRY_SIZE);
	else
		newldt = kmalloc(mincount*LDT_ENTRY_SIZE, GFP_KERNEL);

	if (!newldt)
		return -ENOMEM;

	if (oldsize)
		memcpy(newldt, pc->ldt, oldsize*LDT_ENTRY_SIZE);
	oldldt = pc->ldt;
	memset(newldt+oldsize*LDT_ENTRY_SIZE, 0, (mincount-oldsize)*LDT_ENTRY_SIZE);
	pc->ldt = newldt;
	wmb();
	pc->size = mincount;
	wmb();

	if (reload) {
#ifdef CONFIG_SMP
		cpumask_t mask;
		preempt_disable();
		load_LDT(pc);
		mask = cpumask_of_cpu(smp_processor_id());
		if (!cpus_equal(current->mm->cpu_vm_mask, mask))
			smp_call_function(flush_ldt, NULL, 1, 1);
		preempt_enable();
#else
		load_LDT(pc);
#endif
	}
	if (oldsize) {
		if (oldsize*LDT_ENTRY_SIZE > PAGE_SIZE)
			vfree(oldldt);
		else
			kfree(oldldt);
	}
	return 0;

}

static inline int copy_ldt(mm_context_t *new, mm_context_t *old)
{
	int err = alloc_ldt(new, old->size, 0);
	if (err < 0)
		return err;
	memcpy(new->ldt, old->ldt, old->size*LDT_ENTRY_SIZE);
	return 0;
}

int init_new_context(struct task_struct *tsk, struct mm_struct *mm)
{
	struct mm_struct * old_mm;
	int retval = 0;

	init_MUTEX(&mm->context.sem);
	mm->context.size = 0;
	old_mm = current->mm;
	if (old_mm && old_mm->context.size > 0) {
		down(&old_mm->context.sem);
		retval = copy_ldt(&mm->context, &old_mm->context);
		up(&old_mm->context.sem);
	}
	return retval;
}

void destroy_context(struct mm_struct *mm)
{
	if (mm->context.size) {
		if (mm == current->active_mm)
			clear_LDT();
		if (mm->context.size*LDT_ENTRY_SIZE > PAGE_SIZE)
			vfree(mm->context.ldt);
		else
			kfree(mm->context.ldt);
		mm->context.size = 0;
	}
}