#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <asm/dma.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/timer.h>

#include "cpu.h"

static void __init init_cyrix(struct cpuinfo_x86 *c) {

}

static void cyrix_identify(struct cpuinfo_x86 * c) {

}

static struct cpu_dev cyrix_cpu_dev __initdata = {
	.c_vendor	= "Cyrix",
	.c_ident 	= { "CyrixInstead" },
	.c_init		= init_cyrix,
	.c_identify	= cyrix_identify,
};

int __init cyrix_init_cpu(void) {
	cpu_devs[X86_VENDOR_CYRIX] = &cyrix_cpu_dev;
	return 0;
}

static struct cpu_dev nsc_cpu_dev __initdata = {
	.c_vendor	= "NSC",
	.c_ident 	= { "Geode by NSC" },
	.c_init		= init_cyrix,
	.c_identify	= generic_identify,
};

int __init nsc_init_cpu(void) {
	cpu_devs[X86_VENDOR_NSC] = &nsc_cpu_dev;
	return 0;
}