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

static int noinline do_test_wp_bit(void);

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

static inline int page_kills_ppro(unsigned long pagenr)
{
    mypanic("in page kills ppro");
    return 1;
}

static inline int page_is_ram(unsigned long pagenr)
{
	int i;
	unsigned long addr, end;

	if (efi_enabled) {
        mypanic("efi enabled");
	}

	for (i = 0; i < e820.nr_map; i++) {

		if (e820.map[i].type != E820_RAM)	/* not usable memory */
			continue;
		/*
		 *	!!!FIXME!!! Some BIOSen report areas as RAM that
		 *	are not. Notably the 640->1Mb area. We need a sanity
		 *	check here.
		 */
		addr = (e820.map[i].addr+PAGE_SIZE-1) >> PAGE_SHIFT;
		end = (e820.map[i].addr+e820.map[i].size) >> PAGE_SHIFT;
		if  ((pagenr >= addr) && (pagenr < end))
			return 1;
	}
	return 0;
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

void __init one_highpage_init(struct page *page, int pfn, int bad_ppro)
{
    if (page_is_ram(pfn) && !(bad_ppro && page_kills_ppro(pfn))) {
        ClearPageReserved(page);
        set_bit(PG_highmem, &page->flags);
		set_page_count(page, 1);
		__free_page(page);
		totalhigh_pages++;
    } else
        SetPageReserved(page);
}

#ifndef CONFIG_DISCONTIGMEM
void __init set_highmem_pages_init(int bad_ppro) 
{
	int pfn;
	for (pfn = highstart_pfn; pfn < highend_pfn; pfn++)
		one_highpage_init(pfn_to_page(pfn), pfn, bad_ppro);
	totalram_pages += totalhigh_pages;
}
#else
extern void set_highmem_pages_init(int);
#endif /* !CONFIG_DISCONTIGMEM */

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

void __init test_wp_bit(void) {
    printk("Checking if this processor honours the WP bit even in supervisor mode... ");

	/* Any page-aligned address will do, the test is non-destructive */
	__set_fixmap(FIX_WP_TEST, __pa(&swapper_pg_dir), PAGE_READONLY);
	boot_cpu_data.wp_works_ok = do_test_wp_bit();
	clear_fixmap(FIX_WP_TEST);

	if (!boot_cpu_data.wp_works_ok) {
		printk("No.\n");
#ifdef CONFIG_X86_WP_WORKS_OK
		panic("This kernel doesn't support CPU's with broken WP. Recompile it for a 386!");
#endif
	} else {
		printk("Ok.\n");
	}
}

#ifndef CONFIG_DISCONTIGMEM
static void __init set_max_mapnr_init(void)
{
#ifdef CONFIG_HIGHMEM
	max_mapnr = num_physpages = highend_pfn;
#else
#error "!CONFIG_HIGHMEM"
#endif
}
#define __free_all_bootmem() free_all_bootmem()
#else
#error "CONFIG_DISCONTIGMEM"
#endif /* !CONFIG_DISCONTIGMEM */

static struct kcore_list kcore_mem, kcore_vmalloc; 

void __init mem_init(void)
{
	extern int ppro_with_ram_bug(void);
	int codesize, reservedpages, datasize, initsize;
	int tmp;
	int bad_ppro;

#ifndef CONFIG_DISCONTIGMEM
	if (!mem_map)
		BUG();
#endif
	
	bad_ppro = ppro_with_ram_bug();

#ifdef CONFIG_HIGHMEM
	/* check that fixmap and pkmap do not overlap */
	if (PKMAP_BASE+LAST_PKMAP*PAGE_SIZE >= FIXADDR_START) {
		printk(KERN_ERR "fixmap and kmap areas overlap - this will crash\n");
		printk(KERN_ERR "pkstart: %lxh pkend: %lxh fixstart %lxh\n",
				PKMAP_BASE, PKMAP_BASE+LAST_PKMAP*PAGE_SIZE, FIXADDR_START);
		BUG();
	}
#endif

    set_max_mapnr_init();

#ifdef CONFIG_HIGHMEM
	high_memory = (void *) __va(highstart_pfn * PAGE_SIZE);
#else
#error "!CONFIG_HIGHMEM"
#endif

    /* this will put all low memory onto the freelists */
	totalram_pages += __free_all_bootmem();

    reservedpages = 0;
	for (tmp = 0; tmp < max_low_pfn; tmp++)
		/*
		 * Only count reserved RAM pages
		 */
		if (page_is_ram(tmp) && PageReserved(pfn_to_page(tmp)))
			reservedpages++;

    set_highmem_pages_init(bad_ppro);

    codesize =  (unsigned long) &_etext - (unsigned long) &_text;
	datasize =  (unsigned long) &_edata - (unsigned long) &_etext;
	initsize =  (unsigned long) &__init_end - (unsigned long) &__init_begin;

    kclist_add(&kcore_mem, __va(0), max_low_pfn << PAGE_SHIFT);
    kclist_add(&kcore_vmalloc, (void *)VMALLOC_START, 
		   VMALLOC_END-VMALLOC_START);
    
    printk(KERN_INFO "Memory: %luk/%luk available (%dk kernel code, %dk reserved, %dk data, %dk init, %ldk highmem)\n",
		(unsigned long) nr_free_pages() << (PAGE_SHIFT-10),
		num_physpages << (PAGE_SHIFT-10),
		codesize >> 10,
		reservedpages << (PAGE_SHIFT-10),
		datasize >> 10,
		initsize >> 10,
		(unsigned long) (totalhigh_pages << (PAGE_SHIFT-10))
	       );
    
#ifdef CONFIG_X86_PAE
#error "CONFIG_X86_PAE"
#endif
	if (boot_cpu_data.wp_works_ok < 0)
		test_wp_bit();

	/*
	 * Subtle. SMP is doing it's boot stuff late (because it has to
	 * fork idle threads) - but it also needs low mappings for the
	 * protected-mode entry to work. We zap these entries only after
	 * the WP-bit has been tested.
	 */
#ifndef CONFIG_SMP
#error "!CONFIG_SMP"
#endif
}

/*
 * This function cannot be __init, since exceptions don't work in that
 * section.  Put this after the callers, so that it cannot be inlined.
 */
static int noinline do_test_wp_bit(void)
{
	char tmp_reg;
	int flag;

	__asm__ __volatile__(
		"	movb %0,%1	\n"
		"1:	movb %1,%0	\n"
		"	xorl %2,%2	\n"
		"2:			\n"
		".section __ex_table,\"a\"\n"
		"	.align 4	\n"
		"	.long 1b,2b	\n"
		".previous		\n"
		:"=m" (*(char *)fix_to_virt(FIX_WP_TEST)),
		 "=q" (tmp_reg),
		 "=r" (flag)
		:"2" (1)
		:"memory");
	
	return flag;
}