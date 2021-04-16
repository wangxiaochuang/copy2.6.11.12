#include <linux/sysdev.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/pm.h>
#include <linux/pci.h>

#include <acpi/acpi_bus.h>
#include <acpi/acpi_drivers.h>

static int acpi_irq_balance;	/* 0: static, 1: balance */

int __init acpi_irq_balance_set(char *str)
{
	acpi_irq_balance = 1;
	return 1;
}
__setup("acpi_irq_balance", acpi_irq_balance_set);