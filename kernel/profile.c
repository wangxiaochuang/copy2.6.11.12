#include <linux/config.h>
#include <linux/module.h>
#include <linux/profile.h>
#include <linux/bootmem.h>
#include <linux/notifier.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/profile.h>
#include <linux/highmem.h>
#include <asm/sections.h>
#include <asm/semaphore.h>

struct profile_hit {
	u32 pc, hits;
};
#define PROFILE_GRPSHIFT	3
#define PROFILE_GRPSZ		(1 << PROFILE_GRPSHIFT)
#define NR_PROFILE_HIT		(PAGE_SIZE/sizeof(struct profile_hit))
#define NR_PROFILE_GRP		(NR_PROFILE_HIT/PROFILE_GRPSZ)

/* Oprofile timer tick hook */
int (*timer_hook)(struct pt_regs *);

static atomic_t *prof_buffer;
static unsigned long prof_len, prof_shift;
static int prof_on;
static cpumask_t prof_cpu_mask = CPU_MASK_ALL;
#ifdef CONFIG_SMP
static DEFINE_PER_CPU(struct profile_hit *[2], cpu_profile_hits);
static DEFINE_PER_CPU(int, cpu_profile_flip);
static DECLARE_MUTEX(profile_flip_mutex);
#endif /* CONFIG_SMP */

void __init profile_init(void) {
    if (!prof_on)
        return;
    /* only text is profiled */
	prof_len = (_etext - _stext) >> prof_shift;
	prof_buffer = alloc_bootmem(prof_len*sizeof(atomic_t));
}

void profile_hit(int type, void *__pc)
{
	unsigned long primary, secondary, flags, pc = (unsigned long)__pc;
	int i, j, cpu;
	struct profile_hit *hits;

	if (prof_on != type || !prof_buffer)
		return;
	pc = min((pc - (unsigned long)_stext) >> prof_shift, prof_len - 1);
	i = primary = (pc & (NR_PROFILE_GRP - 1)) << PROFILE_GRPSHIFT;
	secondary = (~(pc << 1) & (NR_PROFILE_GRP - 1)) << PROFILE_GRPSHIFT;
	cpu = get_cpu();
	hits = per_cpu(cpu_profile_hits, cpu)[per_cpu(cpu_profile_flip, cpu)];
	if (!hits) {
		put_cpu();
		return;
	}
	local_irq_save(flags);
	do {
		for (j = 0; j < PROFILE_GRPSZ; ++j) {
			if (hits[i + j].pc == pc) {
				hits[i + j].hits++;
				goto out;
			} else if (!hits[i + j].hits) {
				hits[i + j].pc = pc;
				hits[i + j].hits = 1;
				goto out;
			}
		}
		i = (i + secondary) & (NR_PROFILE_HIT - 1);
	} while (i != primary);
	atomic_inc(&prof_buffer[pc]);
	for (i = 0; i < NR_PROFILE_HIT; ++i) {
		atomic_add(hits[i].hits, &prof_buffer[hits[i].pc]);
		hits[i].pc = hits[i].hits = 0;
	}
out:
	local_irq_restore(flags);
	put_cpu();
}

void profile_tick(int type, struct pt_regs *regs)
{
	if (type == CPU_PROFILING && timer_hook)
		timer_hook(regs);
	if (!user_mode(regs) && cpu_isset(smp_processor_id(), prof_cpu_mask))
		profile_hit(type, (void *)profile_pc(regs));
}