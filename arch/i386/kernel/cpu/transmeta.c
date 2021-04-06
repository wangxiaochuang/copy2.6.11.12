#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include "cpu.h"

static void __init init_transmeta(struct cpuinfo_x86 *c) {

}

static void transmeta_identify(struct cpuinfo_x86 * c) {

}

static struct cpu_dev transmeta_cpu_dev __initdata = {
	.c_vendor	= "Transmeta",
	.c_ident	= { "GenuineTMx86", "TransmetaCPU" },
	.c_init		= init_transmeta,
	.c_identify	= transmeta_identify,
};

int __init transmeta_init_cpu(void)
{
	cpu_devs[X86_VENDOR_TRANSMETA] = &transmeta_cpu_dev;
	return 0;
}