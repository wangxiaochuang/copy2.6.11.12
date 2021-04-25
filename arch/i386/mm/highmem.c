#include <linux/highmem.h>

void *kmap_atomic(struct page *page, enum km_type type)
{
	enum fixed_addresses idx;
	unsigned long vaddr;

    inc_preempt_count();
    if (!PageHighMem(page))
        return page_address(page);
    
    idx = type + KM_TYPE_NR*smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);

    set_pte(kmap_pte - idx, mk_pte(page, kmap_prot));
    __flush_tlb_one(vaddr);

	return (void*) vaddr;
}

void kunmap_atomic(void *kvaddr, enum km_type type)
{
    dec_preempt_count();
	preempt_check_resched();
}