#include <linux/module.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/pm.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#ifdef CONFIG_X86
#include <asm/mpspec.h>
#endif
#include <acpi/acpi_bus.h>
#include <acpi/acpi_drivers.h>

FADT_DESCRIPTOR			acpi_fadt;
EXPORT_SYMBOL(acpi_fadt);