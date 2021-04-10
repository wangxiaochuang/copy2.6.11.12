#include <linux/init.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <asm/semaphore.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/mmu_context.h>
#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <mach_apic.h>
#endif

#include "cpu.h"

struct cpu_dev * cpu_devs[X86_VENDOR_NUM] = {};

static void default_init(struct cpuinfo_x86 * c) {
    if (c->cpuid_level == -1) {
        if (c->x86 == 4)
            strcpy(c->x86_model_id, "486");
        else if (c->x86 == 3)
            strcpy(c->x86_model_id, "386");
    }
}
static struct cpu_dev default_cpu = {
	.c_init	= default_init,
};
static struct cpu_dev * this_cpu = &default_cpu;

void __init get_cpu_vendor(struct cpuinfo_x86 *c, int early) {
    char *v = c->x86_vendor_id;
    int i;
    for (i = 0; i < X86_VENDOR_NUM; i++) {
        if (cpu_devs[i]) {
            if (!strcmp(v, cpu_devs[i]->c_ident[0]) ||
                (cpu_devs[i]->c_ident[1] &&
                !strcmp(v, cpu_devs[i]->c_ident[1]))) {
                    c->x86_vendor = i;
                    if (!early)
                        this_cpu = cpu_devs[i];
                    break;
                }
        }
    }
}

static inline int flag_is_changeable_p(u32 flag) {
	u32 f1, f2;

	asm("pushfl\n\t"
	    "pushfl\n\t"
	    "popl %0\n\t"
	    "movl %0,%1\n\t"
	    "xorl %2,%0\n\t"
	    "pushl %0\n\t"
	    "popfl\n\t"
	    "pushfl\n\t"
	    "popl %0\n\t"
	    "popfl\n\t"
	    : "=&r" (f1), "=&r" (f2)
	    : "ir" (flag));

	return ((f1^f2) & flag) != 0;
}

int __init have_cpuid_p(void) {
	return flag_is_changeable_p(X86_EFLAGS_ID);
}

void __init early_cpu_detect(void) {
    struct cpuinfo_x86 *c = &boot_cpu_data;
    c->x86_cache_alignment = 32;

    if (!have_cpuid_p())
        return;
    cpuid(0x00000000, &c->cpuid_level,
	      (int *)&c->x86_vendor_id[0],
	      (int *)&c->x86_vendor_id[8],
	      (int *)&c->x86_vendor_id[4]);
    get_cpu_vendor(c, 1);

    c->x86 = 4;
    if (c->cpuid_level >= 0x00000001) {
        u32 junk, tfms, cap0, misc;
		cpuid(0x00000001, &tfms, &misc, &junk, &cap0);
        // bochs: 6 3
        c->x86 = (tfms >> 8) & 15;
		c->x86_model = (tfms >> 4) & 15;
        if (c->x86 == 0xf) {
			c->x86 += (tfms >> 20) & 0xff;
			c->x86_model += ((tfms >> 16) & 0xF) << 4;
		}
        c->x86_mask = tfms & 15;
		if (cap0 & (1<<19))
			c->x86_cache_alignment = ((misc >> 8) & 0xff) * 8;
    }
    early_intel_workaround(c);
}

void __init generic_identify(struct cpuinfo_x86 * c) {
    
}

void __init identify_cpu(struct cpuinfo_x86 *c) {
    
}

extern int intel_cpu_init(void);
extern int cyrix_init_cpu(void);
extern int nsc_init_cpu(void);
extern int amd_init_cpu(void);
extern int centaur_init_cpu(void);
extern int transmeta_init_cpu(void);
extern int rise_init_cpu(void);
extern int nexgen_init_cpu(void);
extern int umc_init_cpu(void);
void early_cpu_detect(void);

void __init early_cpu_init(void) {
    intel_cpu_init();
    cyrix_init_cpu();
    nsc_init_cpu();
	amd_init_cpu();
	centaur_init_cpu();
	transmeta_init_cpu();
	rise_init_cpu();
	nexgen_init_cpu();
	umc_init_cpu();
    early_cpu_detect();
#ifdef CONFIG_DEBUG_PAGEALLOC
#error "CONFIG_DEBUG_PAGEALLOC"
#endif
}