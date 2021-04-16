/*
 *	Implement 'Simple Boot Flag Specification 2.0'
 */


#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/acpi.h>
#include <asm/io.h>

#include <linux/mc146818rtc.h>


#define SBF_RESERVED (0x78)
#define SBF_PNPOS    (1<<0)
#define SBF_BOOTING  (1<<1)
#define SBF_DIAG     (1<<2)
#define SBF_PARITY   (1<<7)


int sbf_port __initdata = -1;	/* set via acpi_boot_init() */