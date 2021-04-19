#include <linux/pci.h>
#include <linux/init.h>
#include "pci.h"

/* The physical address of the MMCONFIG aperture.  Set from ACPI tables. */
u32 pci_mmcfg_base_addr;