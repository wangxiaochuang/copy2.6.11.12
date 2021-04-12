#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/spinlock.h>
#include <linux/bootmem.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/efi.h>

#include <asm/setup.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/tlbflush.h>

struct efi_memory_map memmap __initdata;

u32 efi_mem_type(unsigned long phys_addr)
{
	efi_memory_desc_t *md;
	int i;

	for (i = 0; i < memmap.nr_map; i++) {
		md = &memmap.map[i];
		if ((md->phys_addr <= phys_addr) && (phys_addr <
			(md->phys_addr + (md-> num_pages << EFI_PAGE_SHIFT)) ))
			return md->type;
	}
	return 0;
}