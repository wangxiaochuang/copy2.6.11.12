#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <acpi/acpi_bus.h>
#include <linux/dmi.h>

int __init acpi_blacklisted(void) {
    return 0;
}