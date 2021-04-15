#include <linux/config.h>
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/efi.h>

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/dma.h>
#include <asm/fixmap.h>
#include <asm/e820.h>
#include <asm/apic.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>

unsigned int __VMALLOC_RESERVE = 128 << 20;

unsigned long highstart_pfn, highend_pfn;

static pmd_t * __init one_md_table_init(pgd_t *pgd) {
    pud_t *pud;
    pmd_t *pmd_table;
#ifdef CONFIG_X86_PAE
#error "CONFIG_X86_PAE"
#else
    pud = pud_offset(pgd, 0);
    pmd_table = pmd_offset(pud, 0);
#endif
    return pmd_table;
}

static pte_t * __init one_page_table_init(pmd_t *pmd) {
    if (pmd_none(*pmd)) {
        // 分配一页用作页表
        pte_t *page_table = (pte_t *) alloc_bootmem_low_pages(PAGE_SIZE);
        set_pmd(pmd, __pmd(__pa(page_table) | _PAGE_TABLE));
        if (page_table != pte_offset_kernel(pmd, 0))
            BUG();
        return page_table;
    }
    return pte_offset_kernel(pmd, 0);
}

static void __init page_table_range_init (unsigned long start, unsigned long end, pgd_t *pgd_base) {
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	int pgd_idx, pmd_idx;
	unsigned long vaddr;

    vaddr = start;
    pgd_idx = pgd_index(vaddr);
    pmd_idx = pmd_index(vaddr);
    pgd = pgd_base + pgd_idx;

    for (; (pgd_idx < PTRS_PER_PGD) && (vaddr != end); pgd++, pgd_idx++) {
        if (pgd_none(*pgd))
            one_md_table_init(pgd);
        pud = pud_offset(pgd, vaddr);
        pmd = pmd_offset(pud, vaddr);
        for (; (pmd_idx < PTRS_PER_PMD) && (vaddr != end); pmd++, pmd_idx++) {
            if (pmd_none(*pmd))
                one_page_table_init(pmd);
            vaddr += PMD_SIZE;
        }
        pmd_idx = 0;
    }
}

static inline int is_kernel_text(unsigned long addr) {
    if (addr >= PAGE_OFFSET && addr <= (unsigned long)__init_end)
        return 1;
    return 0;
}

/*
 * This maps the physical memory to kernel virtual address space, a total 
 * of max_low_pfn pages, by creating page tables starting from address 
 * PAGE_OFFSET.
 */
static void __init kernel_physical_mapping_init(pgd_t *pgd_base) {
    unsigned long pfn;
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    int pgd_idx, pmd_idx, pte_ofs;

    // 3G位置在全局描述符表中的索引
    pgd_idx = pgd_index(PAGE_OFFSET);
    pgd = pgd_base + pgd_idx;
    pfn = 0;

    // 这里将物理地址全部映射到内核虚拟地址开始处
    for (; pgd_idx < PTRS_PER_PGD; pgd++, pgd_idx++) {
        pmd = one_md_table_init(pgd);
        if (pfn >= max_low_pfn)
            continue;
        for (pmd_idx = 0; pmd_idx < PTRS_PER_PMD && pfn < max_low_pfn; pmd++, pmd_idx++) {
            unsigned int address = pfn * PAGE_SIZE + PAGE_OFFSET;
            if (cpu_has_pse) {
                unsigned int address2 = (pfn + PTRS_PER_PTE - 1) * PAGE_SIZE + PAGE_OFFSET + PAGE_SIZE - 1;
                if (is_kernel_text(address) || is_kernel_text(address2)) {
                    set_pmd(pmd, pfn_pmd(pfn, PAGE_KERNEL_LARGE_EXEC));
                } else
                    set_pmd(pmd, pfn_pmd(pfn, PAGE_KERNEL_LARGE));
                pfn += PTRS_PER_PTE;
            } else {
                pte = one_page_table_init(pmd);

                for (pte_ofs = 0; pte_ofs < PTRS_PER_PTE && pfn < max_low_pfn; pte++, pfn++, pte_ofs++) {
                    if (is_kernel_text(address))
                        set_pte(pte, pfn_pte(pfn, PAGE_KERNEL_EXEC));
                    else
                        set_pte(pte, pfn_pte(pfn, PAGE_KERNEL));
                }
            }
        }
    }
}

#ifdef CONFIG_HIGHMEM
pte_t *kmap_pte;
pgprot_t kmap_prot;

EXPORT_SYMBOL(kmap_prot);
EXPORT_SYMBOL(kmap_pte);

#define kmap_get_fixmap_pte(vaddr)					\
	pte_offset_kernel(pmd_offset(pud_offset(pgd_offset_k(vaddr), vaddr), (vaddr)), (vaddr))

void __init kmap_init(void) {
    unsigned long kmap_vstart;

    /* cache the first kmap pte */
    kmap_vstart = __fix_to_virt(FIX_KMAP_BEGIN);
    kmap_pte = kmap_get_fixmap_pte(kmap_vstart);

    kmap_prot = PAGE_KERNEL;
}

void __init permanent_kmaps_init(pgd_t *pgd_base) {
    pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long vaddr;

	vaddr = PKMAP_BASE;
    page_table_range_init(vaddr, vaddr + PAGE_SIZE * LAST_PKMAP, pgd_base);

    pgd = swapper_pg_dir + pgd_index(vaddr);
    pud = pud_offset(pgd, vaddr);
    pmd = pmd_offset(pud, vaddr);
    pte = pte_offset_kernel(pmd, vaddr);
    pkmap_page_table = pte;
}

#else
#define kmap_init() do { } while (0)
#define permanent_kmaps_init(pgd_base) do { } while (0)
#define set_highmem_pages_init(bad_ppro) do { } while (0)
#endif /* CONFIG_HIGHMEM */

unsigned long long __PAGE_KERNEL = _PAGE_KERNEL;
unsigned long long __PAGE_KERNEL_EXEC = _PAGE_KERNEL_EXEC;

#ifndef CONFIG_DISCONTIGMEM
#define remap_numa_kva() do {} while (0)
#else
extern void __init remap_numa_kva(void);
#endif

#ifndef CONFIG_DISCONTIGMEM
void __init zone_sizes_init(void) {
    unsigned long zones_size[MAX_NR_ZONES] = {0, 0, 0};
    unsigned int max_dma, high, low;

    max_dma = virt_to_phys((char *) MAX_DMA_ADDRESS) >> PAGE_SHIFT;
    low = max_low_pfn;
    high = highend_pfn;
    if (low < max_dma)
        zones_size[ZONE_DMA] = low;
    else {
        zones_size[ZONE_DMA] = max_dma;
        zones_size[ZONE_NORMAL] = low - max_dma;
#ifdef CONFIG_HIGHMEM
        zones_size[ZONE_HIGHMEM] = high - low;
#endif
    }
    free_area_init(zones_size);
}
#else
#error "CONFIG_DISCONTIGMEM"
#endif

static void __init pagetable_init (void) {
    unsigned long vaddr;
	pgd_t *pgd_base = swapper_pg_dir;
#ifdef CONFIG_X86_PAE
#error "CONFIG_X86_PAE"
#endif

    if (cpu_has_pse) {
        set_in_cr4(X86_CR4_PSE);
    }
    if (cpu_has_pge) {
        set_in_cr4(X86_CR4_PGE);
        __PAGE_KERNEL |= _PAGE_GLOBAL;
        __PAGE_KERNEL_EXEC |= _PAGE_GLOBAL;
    }
    // 将所有的低端物理内存映射到内核虚拟地址
    kernel_physical_mapping_init(pgd_base);
    remap_numa_kva();

    // 虚拟地址也有分配，固定区域放在虚拟内存的高地址处
    // 这里得到的地址是将高地址处的固定映射区排除后的地址
    vaddr = __fix_to_virt(__end_of_fixed_addresses - 1) & PMD_MASK;
    // 这里将固定映射区的页目录表填写好了并分配了页表
    // 页目录项分配页表映射这些固定映射区
    page_table_range_init(vaddr, 0, pgd_base);

    // kmaps虚拟内存区域映射
    permanent_kmaps_init(pgd_base);
}

static int disable_nx __initdata = 0;
u64 __supported_pte_mask = ~_PAGE_NX;

/*
 * noexec = on|off
 *
 * Control non executable mappings.
 *
 * on      Enable
 * off     Disable
 */
void __init noexec_setup(const char *str) {
    if (!strncmp(str, "on",2) && cpu_has_nx) {
		__supported_pte_mask |= _PAGE_NX;
		disable_nx = 0;
	} else if (!strncmp(str,"off",3)) {
		disable_nx = 1;
		__supported_pte_mask &= ~_PAGE_NX;
	}
}

void __init paging_init(void) {
#ifdef CONFIG_X86_PAE
#error "CONFIG_X86_PAE"
#endif
    pagetable_init();

    load_cr3(swapper_pg_dir);

#ifdef CONFIG_X86_PAE
#error "CONFIG_X86_PAE"
#endif

    __flush_tlb_all();

    // 固定映射区已经映射了，这里只是缓存一下全局变量
    kmap_init();
    /**
     * 内存可以有多个node
     * 每一个node都有多个zone（DMZ、NORMAL、HIGHMEM）
     **/
    zone_sizes_init();
}