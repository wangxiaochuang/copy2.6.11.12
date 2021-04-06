#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/e820.h>
#include "cpu.h"

static void __init init_centaur(struct cpuinfo_x86 *c) {
    
}

static unsigned int centaur_size_cache(struct cpuinfo_x86 * c, unsigned int size) {
    return 0;
}

static struct cpu_dev centaur_cpu_dev __initdata = {
	.c_vendor	= "Centaur",
	.c_ident	= { "CentaurHauls" },
	.c_init		= init_centaur,
	.c_size_cache	= centaur_size_cache,
};

int __init centaur_init_cpu(void) {
	cpu_devs[X86_VENDOR_CENTAUR] = &centaur_cpu_dev;
	return 0;
}