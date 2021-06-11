#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/acct.h>
#include <linux/module.h>
#include <linux/init.h>

#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#include <linux/swapops.h>
#include <linux/elf.h>

#ifndef CONFIG_DISCONTIGMEM
/* use the per-pgdat data instead for discontigmem - mbligh */
unsigned long max_mapnr;
struct page *mem_map;

EXPORT_SYMBOL(max_mapnr);
EXPORT_SYMBOL(mem_map);
#endif

unsigned long num_physpages;
/*
 * A number of key systems in x86 including ioremap() rely on the assumption
 * that high_memory defines the upper bound on direct map memory, then end
 * of ZONE_NORMAL.  Under CONFIG_DISCONTIG this means that max_low_pfn and
 * highstart_pfn must be the same; there must be no gap between ZONE_NORMAL
 * and ZONE_HIGHMEM.
 */
void * high_memory;
unsigned long vmalloc_earlyreserve;

EXPORT_SYMBOL(num_physpages);
EXPORT_SYMBOL(high_memory);
EXPORT_SYMBOL(vmalloc_earlyreserve);

pte_t fastcall * pte_alloc_map(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	if (!pmd_present(*pmd)) {
		struct page *new;

		spin_unlock(&mm->page_table_lock);
		new = pte_alloc_one(mm, address);
		spin_lock(&mm->page_table_lock);
		if (!new)
			return NULL;

		if (pmd_present(*pmd)) {
			pte_free(new);
			goto out;
		}
		mm->nr_ptes++;
		inc_page_state(nr_page_table_pages);
		pmd_populate(mm, pmd, new);
	}
out:
	return pte_offset_map(pmd, address);
}

pte_t fastcall * pte_alloc_kernel(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
    if (!pmd_present(*pmd)) {
        pte_t *new;

        spin_unlock(&mm->page_table_lock);
		new = pte_alloc_one_kernel(mm, address);
		spin_lock(&mm->page_table_lock);
		if (!new)
			return NULL;

        /*
		 * Because we dropped the lock, we should re-check the
		 * entry, as somebody else could have populated it..
		 */
		if (pmd_present(*pmd)) {
			pte_free_kernel(new);
			goto out;
		}
		pmd_populate_kernel(mm, pmd, new);
    }
out:
	return pte_offset_kernel(pmd, address);
}

static inline void
copy_swap_pte(struct mm_struct *dst_mm, struct mm_struct *src_mm, pte_t pte)
{
	panic("in copy_swap_pte function");
}

static inline void
copy_one_pte(struct mm_struct *dst_mm,  struct mm_struct *src_mm,
		pte_t *dst_pte, pte_t *src_pte, unsigned long vm_flags,
		unsigned long addr)
{
	pte_t pte = *src_pte;
	struct page *page;
	unsigned long pfn;

	if (!pte_present(pte)) {
		copy_swap_pte(dst_mm, src_mm, pte);
		set_pte(dst_pte, pte);
		return;
	}
	pfn = pte_pfn(pte);

	page = NULL;
	if (pfn_valid(pfn))
		page = pfn_to_page(pfn);

	if (!page || PageReserved(page)) {
		set_pte(dst_pte, pte);
		return;
	}

	if ((vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE) {
		ptep_set_wrprotect(src_pte);
		pte = *src_pte;
	}

	if (vm_flags & VM_SHARED)
		pte = pte_mkclean(pte);
	pte = pte_mkold(pte);
	get_page(page);
	dst_mm->rss++;
	if (PageAnon(page))
		dst_mm->anon_rss++;
	set_pte(dst_pte, pte);
	page_dup_rmap(page);
}

static int copy_pte_range(struct mm_struct *dst_mm,  struct mm_struct *src_mm,
		pmd_t *dst_pmd, pmd_t *src_pmd, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pte_t *src_pte, *dst_pte;
	pte_t *s, *d;
	unsigned long vm_flags = vma->vm_flags;

	d = dst_pte = pte_alloc_map(dst_mm, dst_pmd, addr);
	if (!dst_pte)
		return -ENOMEM;

	spin_lock(&src_mm->page_table_lock);
	s = src_pte = pte_offset_map_nested(src_pmd, addr);
	for (; addr < end; addr += PAGE_SIZE, s++, d++) {
		if (pte_none(*s))
			continue;
		copy_one_pte(dst_mm, src_mm, d, s, vm_flags, addr);
	}
	pte_unmap_nested(src_pte);
	pte_unmap(dst_pte);
	spin_unlock(&src_mm->page_table_lock);
	cond_resched_lock(&dst_mm->page_table_lock);
	return 0;
}

static int copy_pmd_range(struct mm_struct *dst_mm,  struct mm_struct *src_mm,
		pud_t *dst_pud, pud_t *src_pud, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pmd_t *src_pmd, *dst_pmd;
	int err = 0;
	unsigned long next;

	src_pmd = pmd_offset(src_pud, addr);
	dst_pmd = pmd_alloc(dst_mm, dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;

	for (; addr < end; addr = next, src_pmd++, dst_pmd++) {
		next = (addr + PMD_SIZE) & PMD_MASK;
		if (next > end || next <= addr)
			next = end;
		if (pmd_none(*src_pmd))
			continue;
		if (pmd_bad(*src_pmd)) {
			pmd_ERROR(*src_pmd);
			pmd_clear(src_pmd);
			continue;
		}
		err = copy_pte_range(dst_mm, src_mm, dst_pmd, src_pmd,
							vma, addr, next);
		if (err)
			break;
	}
	return err;
}

static int copy_pud_range(struct mm_struct *dst_mm,  struct mm_struct *src_mm,
		pgd_t *dst_pgd, pgd_t *src_pgd, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pud_t *src_pud, *dst_pud;
	int err = 0;
	unsigned long next;

	src_pud = pud_offset(src_pgd, addr);
	dst_pud = pud_alloc(dst_mm, dst_pgd, addr);
	if (!dst_pud)
		return -ENOMEM;

	for (;addr < end; addr = next, src_pud++, dst_pud++) {
		next = (addr + PUD_SIZE) & PUD_MASK;
		if (next > end || next <= addr)
			next = end;
		if (pud_none(*src_pud))
			continue;
		if (pud_bad(*src_pud)) {
			pud_ERROR(*src_pud);
			pud_clear(src_pud);
			continue;
		}
		err = copy_pmd_range(dst_mm, src_mm, dst_pud, src_pud,
							vma, addr, next);
		if (err)
			break;
	}
	return err;
}

int copy_page_range(struct mm_struct *dst, struct mm_struct *src,
		struct vm_area_struct *vma)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long addr, start, end, next;
	int err = 0;

	if (is_vm_hugetlb_page(vma))
		return copy_hugetlb_page_range(dst, src, vma);

	start = vma->vm_start;
	src_pgd = pgd_offset(src, start);
	dst_pgd = pgd_offset(dst, start);

	end = vma->vm_end;
	addr = start;
	while (addr && (addr < end - 1)) {
		next = (addr + PGDIR_SIZE) & PGDIR_MASK;
		if (next > end || next <= addr)
			next = end;
		if (pgd_none(*src_pgd))
			goto next_pgd;
		if (pgd_bad(*src_pgd)) {
			pgd_ERROR(*src_pgd);
			pgd_clear(src_pgd);
			goto next_pgd;
		}
		err = copy_pud_range(dst, src, dst_pgd, src_pgd,
							vma, addr, next);
		if (err)
			break;
next_pgd:
		src_pgd++;
		dst_pgd++;
		addr = next;
	}
	return err;
}

static void zap_pte_range(struct mmu_gather *tlb,
		pmd_t *pmd, unsigned long address,
		unsigned long size, struct zap_details *details)
{
	unsigned long offset;
	pte_t *ptep;

	if (pmd_none(*pmd))
		return;
	if (unlikely(pmd_bad(*pmd))) {
		pmd_ERROR(*pmd);
		pmd_clear(pmd);
		return;
	}
	ptep = pte_offset_map(pmd, address);
	offset = address & ~PMD_MASK;
	if (offset + size > PMD_SIZE)
		size = PMD_SIZE - offset;
	size &= PAGE_MASK;
	if (details && !details->check_mapping && !details->nonlinear_vma)
		details = NULL;
	for (offset=0; offset < size; ptep++, offset += PAGE_SIZE) {
		pte_t pte = *ptep;
		if (pte_none(pte))
			continue;
		if (pte_present(pte)) {
			struct page *page = NULL;
			unsigned long pfn = pte_pfn(pte);
			if (pfn_valid(pfn)) {
				page = pfn_to_page(pfn);
				if (PageReserved(page))
					page = NULL;
			}
			if (unlikely(details) && page) {
				/*
				 * unmap_shared_mapping_pages() wants to
				 * invalidate cache without truncating:
				 * unmap shared but keep private pages.
				 */
				if (details->check_mapping &&
				    details->check_mapping != page->mapping)
					continue;
				/*
				 * Each page->index must be checked when
				 * invalidating or truncating nonlinear.
				 */
				if (details->nonlinear_vma &&
				    (page->index < details->first_index ||
				     page->index > details->last_index))
					continue;
			}
			pte = ptep_get_and_clear(ptep);
			tlb_remove_tlb_entry(tlb, ptep, address+offset);
			if (unlikely(!page))
				continue;
			if (unlikely(details) && details->nonlinear_vma
			    && linear_page_index(details->nonlinear_vma,
					address+offset) != page->index)
				set_pte(ptep, pgoff_to_pte(page->index));
			if (pte_dirty(pte))
				set_page_dirty(page);
			if (PageAnon(page))
				tlb->mm->anon_rss--;
			else if (pte_young(pte))
				mark_page_accessed(page);
			tlb->freed++;
			page_remove_rmap(page);
			tlb_remove_page(tlb, page);
			continue;
		}
		/*
		 * If details->check_mapping, we leave swap entries;
		 * if details->nonlinear_vma, we leave file entries.
		 */
		if (unlikely(details))
			continue;
		if (!pte_file(pte))
			free_swap_and_cache(pte_to_swp_entry(pte));
		pte_clear(ptep);
	}
	pte_unmap(ptep-1);
}

static void zap_pmd_range(struct mmu_gather *tlb,
		pud_t *pud, unsigned long address,
		unsigned long size, struct zap_details *details)
{
	pmd_t * pmd;
	unsigned long end;

	if (pud_none(*pud))
		return;
	if (unlikely(pud_bad(*pud))) {
		pud_ERROR(*pud);
		pud_clear(pud);
		return;
	}
	pmd = pmd_offset(pud, address);
	end = address + size;
	if (end > ((address + PUD_SIZE) & PUD_MASK))
		end = ((address + PUD_SIZE) & PUD_MASK);
	do {
		zap_pte_range(tlb, pmd, address, end - address, details);
		address = (address + PMD_SIZE) & PMD_MASK; 
		pmd++;
	} while (address && (address < end));
}

static void zap_pud_range(struct mmu_gather *tlb,
		pgd_t * pgd, unsigned long address,
		unsigned long end, struct zap_details *details)
{
	pud_t * pud;

	if (pgd_none(*pgd))
		return;
	if (unlikely(pgd_bad(*pgd))) {
		pgd_ERROR(*pgd);
		pgd_clear(pgd);
		return;
	}
	pud = pud_offset(pgd, address);
	do {
		zap_pmd_range(tlb, pud, address, end - address, details);
		address = (address + PUD_SIZE) & PUD_MASK; 
		pud++;
	} while (address && (address < end));
}

static void unmap_page_range(struct mmu_gather *tlb,
		struct vm_area_struct *vma, unsigned long address,
		unsigned long end, struct zap_details *details)
{
	unsigned long next;
	pgd_t *pgd;
	int i;

	BUG_ON(address >= end);
	pgd = pgd_offset(vma->vm_mm, address);
	tlb_start_vma(tlb, vma);
	for (i = pgd_index(address); i <= pgd_index(end-1); i++) {
		next = (address + PGDIR_SIZE) & PGDIR_MASK;
		if (next <= address || next > end)
			next = end;
		zap_pud_range(tlb, pgd, address, next, details);
		address = next;
		pgd++;
	}
	tlb_end_vma(tlb, vma);
}

#ifdef CONFIG_PREEMPT
# define ZAP_BLOCK_SIZE	(8 * PAGE_SIZE)
#else
/* No preempt: go for improved straight-line efficiency */
# define ZAP_BLOCK_SIZE	(1024 * PAGE_SIZE)
#endif

int unmap_vmas(struct mmu_gather **tlbp, struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long start_addr,
		unsigned long end_addr, unsigned long *nr_accounted,
		struct zap_details *details)
{
	unsigned long zap_bytes = ZAP_BLOCK_SIZE;
	unsigned long tlb_start = 0;	/* For tlb_finish_mmu */
	int tlb_start_valid = 0;
	int ret = 0;
	spinlock_t *i_mmap_lock = details? details->i_mmap_lock: NULL;
	int fullmm = tlb_is_full_mm(*tlbp);

	for ( ; vma && vma->vm_start < end_addr; vma = vma->vm_next) {
		unsigned long start;
		unsigned long end;

		start = max(vma->vm_start, start_addr);
		if (start >= vma->vm_end)
			continue;
		end = min(vma->vm_end, end_addr);
		if (end <= vma->vm_start)
			continue;

		if (vma->vm_flags & VM_ACCOUNT)
			*nr_accounted += (end - start) >> PAGE_SHIFT;

		ret++;
		while (start != end) {
			unsigned long block;

			if (!tlb_start_valid) {
				tlb_start = start;
				tlb_start_valid = 1;
			}

			if (is_vm_hugetlb_page(vma)) {
				block = end - start;
				unmap_hugepage_range(vma, start, end);
			} else {
				block = min(zap_bytes, end - start);
				unmap_page_range(*tlbp, vma, start,
						start + block, details);
			}

			start += block;
			zap_bytes -= block;
			if ((long)zap_bytes > 0)
				continue;

			tlb_finish_mmu(*tlbp, tlb_start, start);

			if (need_resched() ||
				need_lockbreak(&mm->page_table_lock) ||
				(i_mmap_lock && need_lockbreak(i_mmap_lock))) {
				if (i_mmap_lock) {
					/* must reset count of rss freed */
					*tlbp = tlb_gather_mmu(mm, fullmm);
					details->break_addr = start;
					goto out;
				}
				spin_unlock(&mm->page_table_lock);
				cond_resched();
				spin_lock(&mm->page_table_lock);
			}

			*tlbp = tlb_gather_mmu(mm, fullmm);
			tlb_start_valid = 0;
			zap_bytes = ZAP_BLOCK_SIZE;
		}
	}
out:
	return ret;
}

void zap_page_range(struct vm_area_struct *vma, unsigned long address,
		unsigned long size, struct zap_details *details)
{
	struct mm_struct *mm = vma->vm_mm;
	struct mmu_gather *tlb;
	unsigned long end = address + size;
	unsigned long nr_accounted = 0;

	if (is_vm_hugetlb_page(vma)) {
		zap_hugepage_range(vma, address, size);
		return;
	}

	lru_add_drain();
	spin_lock(&mm->page_table_lock);
	tlb = tlb_gather_mmu(mm, 0);
	unmap_vmas(&tlb, mm, vma, address, end, &nr_accounted, details);
	tlb_finish_mmu(tlb, address, end);
	acct_update_integrals();
	spin_unlock(&mm->page_table_lock);
}

static struct page *
__follow_page(struct mm_struct *mm, unsigned long address, int read, int write)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	unsigned long pfn;
	struct page *page;

	page = follow_huge_addr(mm, address, write);
	if (! IS_ERR(page))
		return page;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		goto out;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		goto out;
	
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		goto out;
	if (pmd_huge(*pmd))
		return follow_huge_pmd(mm, address, pmd, write);

	ptep = pte_offset_map(pmd, address);
	if (!ptep)
		goto out;

	pte = *ptep;
	pte_unmap(ptep);
	if (pte_present(pte)) {
		if (write && !pte_write(pte))
			goto out;
		if (read && !pte_read(pte))
			goto out;
		pfn = pte_pfn(pte);
		if (pfn_valid(pfn)) {
			page = pfn_to_page(pfn);
			if (write && !pte_dirty(pte) && !PageDirty(page))
				set_page_dirty(page);
			mark_page_accessed(page);
			return page;
		}
	}

out:
	return NULL;
}

struct page *
follow_page(struct mm_struct *mm, unsigned long address, int write)
{
	return __follow_page(mm, address, /*read*/0, write);
}

int
check_user_page_readable(struct mm_struct *mm, unsigned long address)
{
	return __follow_page(mm, address, /*read*/1, /*write*/0) != NULL;
}

EXPORT_SYMBOL(check_user_page_readable);

/* 
 * Given a physical address, is there a useful struct page pointing to
 * it?  This may become more complex in the future if we start dealing
 * with IO-aperture pages for direct-IO.
 */

static inline struct page *get_page_map(struct page *page)
{
	if (!pfn_valid(page_to_pfn(page)))
		return NULL;
	return page;
}


static inline int
untouched_anonymous_page(struct mm_struct* mm, struct vm_area_struct *vma,
			 unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	/* Check if the vma is for an anonymous mapping. */
	if (vma->vm_ops && vma->vm_ops->nopage)
		return 0;

	/* Check if page directory entry exists. */
	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return 1;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		return 1;

	/* Check if page middle directory entry exists. */
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		return 1;

	/* There is a pte slot for 'address' in 'mm'. */
	return 0;
}

int get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, int len, int write, int force,
		struct page **pages, struct vm_area_struct **vmas)
{
	int i;
	unsigned int flags;

	/* 
	 * Require read or write permissions.
	 * If 'force' is set, we only require the "MAY" flags.
	 */
	flags = write ? (VM_WRITE | VM_MAYWRITE) : (VM_READ | VM_MAYREAD);
	flags &= force ? (VM_MAYREAD | VM_MAYWRITE) : (VM_READ | VM_WRITE);
	i = 0;

	do {
		struct vm_area_struct *	vma;

		vma = find_extend_vma(mm, start);
		if (!vma && in_gate_area(tsk, start)) {
			unsigned long pg = start & PAGE_MASK;
			struct vm_area_struct *gate_vma = get_gate_vma(tsk);
			pgd_t *pgd;
			pud_t *pud;
			pmd_t *pmd;
			pte_t *pte;
			if (write) /* user gate pages are read-only */
				return i ? : -EFAULT;
			if (pg > TASK_SIZE)
				pgd = pgd_offset_k(pg);
			else
				pgd = pgd_offset_gate(mm, pg);
			BUG_ON(pgd_none(*pgd));
			pud = pud_offset(pgd, pg);
			BUG_ON(pud_none(*pud));
			pmd = pmd_offset(pud, pg);
			BUG_ON(pmd_none(*pmd));
			pte = pte_offset_map(pmd, pg);
			BUG_ON(pte_none(*pte));
			if (pages) {
				pages[i] = pte_page(*pte);
				get_page(pages[i]);
			}
			pte_unmap(pte);
			if (vmas)
				vmas[i] = gate_vma;
			i++;
			start += PAGE_SIZE;
			len--;
			continue;
		}

		if (!vma || (vma->vm_flags & VM_IO)
				|| !(flags & vma->vm_flags))
			return i ? : -EFAULT;

		if (is_vm_hugetlb_page(vma)) {
			i = follow_hugetlb_page(mm, vma, pages, vmas,
						&start, &len, i);
			continue;
		}
		spin_lock(&mm->page_table_lock);
		do {
			struct page *map;
			int lookup_write = write;

			cond_resched_lock(&mm->page_table_lock);
			while (!(map = follow_page(mm, start, lookup_write))) {
				/*
				 * Shortcut for anonymous pages. We don't want
				 * to force the creation of pages tables for
				 * insanly big anonymously mapped areas that
				 * nobody touched so far. This is important
				 * for doing a core dump for these mappings.
				 */
				if (!lookup_write &&
				    untouched_anonymous_page(mm,vma,start)) {
					map = ZERO_PAGE(start);
					break;
				}
				spin_unlock(&mm->page_table_lock);
				switch (handle_mm_fault(mm,vma,start,write)) {
				case VM_FAULT_MINOR:
					tsk->min_flt++;
					break;
				case VM_FAULT_MAJOR:
					tsk->maj_flt++;
					break;
				case VM_FAULT_SIGBUS:
					return i ? i : -EFAULT;
				case VM_FAULT_OOM:
					return i ? i : -ENOMEM;
				default:
					BUG();
				}
				/*
				 * Now that we have performed a write fault
				 * and surely no longer have a shared page we
				 * shouldn't write, we shouldn't ignore an
				 * unwritable page in the page table if
				 * we are forcing write access.
				 */
				lookup_write = write && !force;
				spin_lock(&mm->page_table_lock);
			}
			if (pages) {
				pages[i] = get_page_map(map);
				if (!pages[i]) {
					spin_unlock(&mm->page_table_lock);
					while (i--)
						page_cache_release(pages[i]);
					i = -EFAULT;
					goto out;
				}
				flush_dcache_page(pages[i]);
				if (!PageReserved(pages[i]))
					page_cache_get(pages[i]);
			}
			if (vmas)
				vmas[i] = vma;
			i++;
			start += PAGE_SIZE;
			len--;
		} while(len && start < vma->vm_end);
		spin_unlock(&mm->page_table_lock);
	} while(len);
out:
	return i;
}

EXPORT_SYMBOL(get_user_pages);


static inline pte_t maybe_mkwrite(pte_t pte, struct vm_area_struct *vma)
{
	if (likely(vma->vm_flags & VM_WRITE))
		pte = pte_mkwrite(pte);
	return pte;
}

/*
 * We hold the mm semaphore for reading and vma->vm_mm->page_table_lock
 */
static inline void break_cow(struct vm_area_struct * vma, struct page * new_page, unsigned long address, 
		pte_t *page_table)
{
	pte_t entry;

	flush_cache_page(vma, address);
	entry = maybe_mkwrite(pte_mkdirty(mk_pte(new_page, vma->vm_page_prot)),
			      vma);
	ptep_establish(vma, address, page_table, entry);
	update_mmu_cache(vma, address, entry);
}

static int do_wp_page(struct mm_struct *mm, struct vm_area_struct * vma,
	unsigned long address, pte_t *page_table, pmd_t *pmd, pte_t pte)
{
	struct page *old_page, *new_page;
	unsigned long pfn = pte_pfn(pte);
	pte_t entry;

	if (unlikely(!pfn_valid(pfn))) {
		/*
		 * This should really halt the system so it can be debugged or
		 * at least the kernel stops what it's doing before it corrupts
		 * data, but for the moment just pretend this is OOM.
		 */
		pte_unmap(page_table);
		printk(KERN_ERR "do_wp_page: bogus page at address %08lx\n",
				address);
		spin_unlock(&mm->page_table_lock);
		return VM_FAULT_OOM;
	}

	old_page = pfn_to_page(pfn);

	if (!TestSetPageLocked(old_page)) {
		int reuse = can_share_swap_page(old_page);
		unlock_page(old_page);
		if (reuse) {
			flush_cache_page(vma, address);
			entry = maybe_mkwrite(pte_mkyoung(pte_mkdirty(pte)),
					      vma);
			ptep_set_access_flags(vma, address, page_table, entry, 1);
			update_mmu_cache(vma, address, entry);
			pte_unmap(page_table);
			spin_unlock(&mm->page_table_lock);
			return VM_FAULT_MINOR;
		}
	}
	pte_unmap(page_table);

	/*
	 * Ok, we need to copy. Oh, well..
	 */
	if (!PageReserved(old_page))
		page_cache_get(old_page);
	spin_unlock(&mm->page_table_lock);

	if (unlikely(anon_vma_prepare(vma)))
		goto no_new_page;
	if (old_page == ZERO_PAGE(address)) {
		new_page = alloc_zeroed_user_highpage(vma, address);
		if (!new_page)
			goto no_new_page;
	} else {
		new_page = alloc_page_vma(GFP_HIGHUSER, vma, address);
		if (!new_page)
			goto no_new_page;
		copy_user_highpage(new_page, old_page, address);
	}
	/*
	 * Re-check the pte - we dropped the lock
	 */
	spin_lock(&mm->page_table_lock);
	page_table = pte_offset_map(pmd, address);
	if (likely(pte_same(*page_table, pte))) {
		if (PageAnon(old_page))
			mm->anon_rss--;
		if (PageReserved(old_page)) {
			++mm->rss;
			acct_update_integrals();
			update_mem_hiwater();
		} else
			page_remove_rmap(old_page);
		break_cow(vma, new_page, address, page_table);
		lru_cache_add_active(new_page);
		page_add_anon_rmap(new_page, vma, address);

		/* Free the old page.. */
		new_page = old_page;
	}
	pte_unmap(page_table);
	page_cache_release(new_page);
	page_cache_release(old_page);
	spin_unlock(&mm->page_table_lock);
	return VM_FAULT_MINOR;

no_new_page:
	page_cache_release(old_page);
	return VM_FAULT_OOM;
}



#define is_restart_addr(truncate_count) (!((truncate_count) & ~PAGE_MASK))

static void reset_vma_truncate_counts(struct address_space *mapping)
{
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;

	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, 0, ULONG_MAX)
		vma->vm_truncate_count = 0;
	list_for_each_entry(vma, &mapping->i_mmap_nonlinear, shared.vm_set.list)
		vma->vm_truncate_count = 0;
}

static int unmap_mapping_range_vma(struct vm_area_struct *vma,
		unsigned long start_addr, unsigned long end_addr,
		struct zap_details *details)
{
	unsigned long restart_addr;
	int need_break;

again:
	restart_addr = vma->vm_truncate_count;
	if (is_restart_addr(restart_addr) && start_addr < restart_addr) {
		start_addr = restart_addr;
		if (start_addr >= end_addr) {
			/* Top of vma has been split off since last time */
			vma->vm_truncate_count = details->truncate_count;
			return 0;
		}
	}

	details->break_addr = end_addr;
	zap_page_range(vma, start_addr, end_addr - start_addr, details);

	/*
	 * We cannot rely on the break test in unmap_vmas:
	 * on the one hand, we don't want to restart our loop
	 * just because that broke out for the page_table_lock;
	 * on the other hand, it does no test when vma is small.
	 */
	need_break = need_resched() ||
			need_lockbreak(details->i_mmap_lock);

	if (details->break_addr >= end_addr) {
		/* We have now completed this vma: mark it so */
		vma->vm_truncate_count = details->truncate_count;
		if (!need_break)
			return 0;
	} else {
		/* Note restart_addr in vma's truncate_count field */
		vma->vm_truncate_count = details->break_addr;
		if (!need_break)
			goto again;
	}

	spin_unlock(details->i_mmap_lock);
	cond_resched();
	spin_lock(details->i_mmap_lock);
	return -EINTR;
}

static inline void unmap_mapping_range_tree(struct prio_tree_root *root,
					    struct zap_details *details)
{
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	pgoff_t vba, vea, zba, zea;

restart:
	vma_prio_tree_foreach(vma, &iter, root,
			details->first_index, details->last_index) {
		/* Skip quickly over those we have already dealt with */
		if (vma->vm_truncate_count == details->truncate_count)
			continue;

		vba = vma->vm_pgoff;
		vea = vba + ((vma->vm_end - vma->vm_start) >> PAGE_SHIFT) - 1;
		/* Assume for now that PAGE_CACHE_SHIFT == PAGE_SHIFT */
		zba = details->first_index;
		if (zba < vba)
			zba = vba;
		zea = details->last_index;
		if (zea > vea)
			zea = vea;

		if (unmap_mapping_range_vma(vma,
			((zba - vba) << PAGE_SHIFT) + vma->vm_start,
			((zea - vba + 1) << PAGE_SHIFT) + vma->vm_start,
				details) < 0)
			goto restart;
	}
}

static inline void unmap_mapping_range_list(struct list_head *head,
					    struct zap_details *details)
{
	struct vm_area_struct *vma;

	/*
	 * In nonlinear VMAs there is no correspondence between virtual address
	 * offset and file offset.  So we must perform an exhaustive search
	 * across *all* the pages in each nonlinear VMA, not just the pages
	 * whose virtual address lies outside the file truncation point.
	 */
restart:
	list_for_each_entry(vma, head, shared.vm_set.list) {
		/* Skip quickly over those we have already dealt with */
		if (vma->vm_truncate_count == details->truncate_count)
			continue;
		details->nonlinear_vma = vma;
		if (unmap_mapping_range_vma(vma, vma->vm_start,
					vma->vm_end, details) < 0)
			goto restart;
	}
}

void unmap_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen, int even_cows)
{
	struct zap_details details;
	pgoff_t hba = holebegin >> PAGE_SHIFT;
	pgoff_t hlen = (holelen + PAGE_SIZE - 1) >> PAGE_SHIFT;

	/* Check for overflow. */
	if (sizeof(holelen) > sizeof(hlen)) {
		long long holeend =
			(holebegin + holelen + PAGE_SIZE - 1) >> PAGE_SHIFT;
		if (holeend & ~(long long)ULONG_MAX)
			hlen = ULONG_MAX - hba + 1;
	}

	details.check_mapping = even_cows? NULL: mapping;
	details.nonlinear_vma = NULL;
	details.first_index = hba;
	details.last_index = hba + hlen - 1;
	if (details.last_index < details.first_index)
		details.last_index = ULONG_MAX;
	details.i_mmap_lock = &mapping->i_mmap_lock;

	spin_lock(&mapping->i_mmap_lock);

	/* serialize i_size write against truncate_count write */
	smp_wmb();
	/* Protect against page faults, and endless unmapping loops */
	mapping->truncate_count++;
	/*
	 * For archs where spin_lock has inclusive semantics like ia64
	 * this smp_mb() will prevent to read pagetable contents
	 * before the truncate_count increment is visible to
	 * other cpus.
	 */
	smp_mb();
	if (unlikely(is_restart_addr(mapping->truncate_count))) {
		if (mapping->truncate_count == 0)
			reset_vma_truncate_counts(mapping);
		mapping->truncate_count++;
	}
	details.truncate_count = mapping->truncate_count;

	if (unlikely(!prio_tree_empty(&mapping->i_mmap)))
		unmap_mapping_range_tree(&mapping->i_mmap, &details);
	if (unlikely(!list_empty(&mapping->i_mmap_nonlinear)))
		unmap_mapping_range_list(&mapping->i_mmap_nonlinear, &details);
	spin_unlock(&mapping->i_mmap_lock);
}
EXPORT_SYMBOL(unmap_mapping_range);

int vmtruncate(struct inode * inode, loff_t offset)
{
	panic("in vmtruncate function");
	return 0;
}

static int do_swap_page(struct mm_struct * mm,
	struct vm_area_struct * vma, unsigned long address,
	pte_t *page_table, pmd_t *pmd, pte_t orig_pte, int write_access)
{
	panic("in do_swap_page function");
	return 0;
}

static int
do_anonymous_page(struct mm_struct *mm, struct vm_area_struct *vma,
		pte_t *page_table, pmd_t *pmd, int write_access,
		unsigned long addr)
{
	pte_t entry;
	struct page * page = ZERO_PAGE(addr);

	/* Read-only mapping of ZERO_PAGE. */
	entry = pte_wrprotect(mk_pte(ZERO_PAGE(addr), vma->vm_page_prot));

	/* ..except if it's a write access */
	if (write_access) {
		/* Allocate our own private page. */
		pte_unmap(page_table);
		spin_unlock(&mm->page_table_lock);

		if (unlikely(anon_vma_prepare(vma)))
			goto no_mem;
		page = alloc_zeroed_user_highpage(vma, addr);
		if (!page)
			goto no_mem;

		spin_lock(&mm->page_table_lock);
		page_table = pte_offset_map(pmd, addr);

		if (!pte_none(*page_table)) {
			pte_unmap(page_table);
			page_cache_release(page);
			spin_unlock(&mm->page_table_lock);
			goto out;
		}
		mm->rss++;
		acct_update_integrals();
		update_mem_hiwater();
		entry = maybe_mkwrite(pte_mkdirty(mk_pte(page,
							 vma->vm_page_prot)),
				      vma);
		lru_cache_add_active(page);
		SetPageReferenced(page);
		page_add_anon_rmap(page, vma, addr);
	}

	set_pte(page_table, entry);
	pte_unmap(page_table);

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, addr, entry);
	spin_unlock(&mm->page_table_lock);
out:
	return VM_FAULT_MINOR;
no_mem:
	return VM_FAULT_OOM;
}

static int
do_no_page(struct mm_struct *mm, struct vm_area_struct *vma,
	unsigned long address, int write_access, pte_t *page_table, pmd_t *pmd)
{
	struct page * new_page;
	struct address_space *mapping = NULL;
	pte_t entry;
	unsigned int sequence = 0;
	int ret = VM_FAULT_MINOR;
	int anon = 0;

	if (!vma->vm_ops || !vma->vm_ops->nopage)
		return do_anonymous_page(mm, vma, page_table,
					pmd, write_access, address);
	pte_unmap(page_table);
	spin_unlock(&mm->page_table_lock);

	if (vma->vm_file) {
		mapping = vma->vm_file->f_mapping;
		sequence = mapping->truncate_count;
		smp_rmb(); /* serializes i_size against truncate_count */
	}
retry:
	cond_resched();
	new_page = vma->vm_ops->nopage(vma, address & PAGE_MASK, &ret);

	if (new_page == NOPAGE_SIGBUS)
		return VM_FAULT_SIGBUS;
	if (new_page == NOPAGE_OOM)
		return VM_FAULT_OOM;

	/*
	 * Should we do an early C-O-W break?
	 */
	if (write_access && !(vma->vm_flags & VM_SHARED)) {
		struct page *page;

		if (unlikely(anon_vma_prepare(vma)))
			goto oom;
		page = alloc_page_vma(GFP_HIGHUSER, vma, address);
		if (!page)
			goto oom;
		copy_user_highpage(page, new_page, address);
		page_cache_release(new_page);
		new_page = page;
		anon = 1;
	}

	spin_lock(&mm->page_table_lock);

	if (mapping && unlikely(sequence != mapping->truncate_count)) {
		sequence = mapping->truncate_count;
		spin_unlock(&mm->page_table_lock);
		page_cache_release(new_page);
		goto retry;
	}
	page_table = pte_offset_map(pmd, address);

	if (pte_none(*page_table)) {
		if (!PageReserved(new_page))
			++mm->rss;
		acct_update_integrals();
		update_mem_hiwater();

		flush_icache_page(vma, new_page);
		entry = mk_pte(new_page, vma->vm_page_prot);
		if (write_access)
			entry = maybe_mkwrite(pte_mkdirty(entry), vma);
		set_pte(page_table, entry);
		if (anon) {
			lru_cache_add_active(new_page);
			page_add_anon_rmap(new_page, vma, address);
		} else
			page_add_file_rmap(new_page);
		pte_unmap(page_table);
	} else {
		/* One of our sibling threads was faster, back out. */
		pte_unmap(page_table);
		page_cache_release(new_page);
		spin_unlock(&mm->page_table_lock);
		goto out;
	}

	/* no need to invalidate: a not-present page shouldn't be cached */
	update_mmu_cache(vma, address, entry);
	spin_unlock(&mm->page_table_lock);
out:
	return ret;
oom:
	page_cache_release(new_page);
	ret = VM_FAULT_OOM;
	goto out;
}

static int do_file_page(struct mm_struct * mm, struct vm_area_struct * vma,
	unsigned long address, int write_access, pte_t *pte, pmd_t *pmd)
{
	panic("in do_file_page function");
	return 0;
}

static inline int handle_pte_fault(struct mm_struct *mm,
	struct vm_area_struct * vma, unsigned long address,
	int write_access, pte_t *pte, pmd_t *pmd)
{
	pte_t entry;

	entry = *pte;
	if (!pte_present(entry)) {
		if (pte_none(entry))
			return do_no_page(mm, vma, address, write_access, pte, pmd);
		if (pte_file(entry))
			return do_file_page(mm, vma, address, write_access, pte, pmd);
		return do_swap_page(mm, vma, address, pte, pmd, entry, write_access);
	}

	if (write_access) {
		if (!pte_write(entry))
			return do_wp_page(mm, vma, address, pte, pmd, entry);

		entry = pte_mkdirty(entry);
	}
	entry = pte_mkyoung(entry);
	ptep_set_access_flags(vma, address, pte, entry, write_access);
	update_mmu_cache(vma, address, entry);
	pte_unmap(pte);
	spin_unlock(&mm->page_table_lock);
	return VM_FAULT_MINOR;
}

/*
 * By the time we get here, we already hold the mm semaphore
 */
int handle_mm_fault(struct mm_struct *mm, struct vm_area_struct * vma,
		unsigned long address, int write_access)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	__set_current_state(TASK_RUNNING);

	inc_page_state(pgfault);

	if (is_vm_hugetlb_page(vma))
		return VM_FAULT_SIGBUS;	/* mapping truncation does this. */

	pgd = pgd_offset(mm, address);
	spin_lock(&mm->page_table_lock);

	pud = pud_alloc(mm, pgd, address);
	if (!pud)
		goto oom;

	pmd = pmd_alloc(mm, pud, address);
	if (!pmd)
		goto oom;

	pte = pte_alloc_map(mm, pmd, address);
	if (!pte)
		goto oom;

	return handle_pte_fault(mm, vma, address, write_access, pte, pmd);

 oom:
	spin_unlock(&mm->page_table_lock);
	return VM_FAULT_OOM;
}

#ifndef __ARCH_HAS_4LEVEL_HACK

pud_t fastcall *__pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
    pud_t *new;

	spin_unlock(&mm->page_table_lock);
	new = pud_alloc_one(mm, address);
	spin_lock(&mm->page_table_lock);
	if (!new)
		return NULL;

	if (pgd_present(*pgd)) {
		pud_free(new);
		goto out;
	}
	pgd_populate(mm, pgd, new);
out:
	return pud_offset(pgd, address);
}

pmd_t fastcall *__pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
    pmd_t *new;

	spin_unlock(&mm->page_table_lock);
	new = pmd_alloc_one(mm, address);
	spin_lock(&mm->page_table_lock);
	if (!new)
		return NULL;

	/*
	 * Because we dropped the lock, we should re-check the
	 * entry, as somebody else could have populated it..
	 */
	if (pud_present(*pud)) {
		pmd_free(new);
		goto out;
	}
	pud_populate(mm, pud, new);
 out:
	return pmd_offset(pud, address);
}


#else
#endif

int make_pages_present(unsigned long addr, unsigned long end)
{
	int ret, len, write;
	struct vm_area_struct * vma;

	vma = find_vma(current->mm, addr);
	if (!vma)
		return -1;
	write = (vma->vm_flags & VM_WRITE) != 0;
	if (addr >= end)
		BUG();
	if (end > vma->vm_end)
		BUG();
	len = (end+PAGE_SIZE-1)/PAGE_SIZE-addr/PAGE_SIZE;
	ret = get_user_pages(current, current->mm, addr,
			len, write, 0, NULL, NULL);
	if (ret < 0)
		return ret;
	return ret == len ? 0 : -1;
}

/*
 * update_mem_hiwater
 *	- update per process rss and vm high water data
 */
void update_mem_hiwater(void)
{
	struct task_struct *tsk = current;

	if (tsk->mm) {
		if (tsk->mm->hiwater_rss < tsk->mm->rss)
			tsk->mm->hiwater_rss = tsk->mm->rss;
		if (tsk->mm->hiwater_vm < tsk->mm->total_vm)
			tsk->mm->hiwater_vm = tsk->mm->total_vm;
	}
}

#if !defined(__HAVE_ARCH_GATE_AREA)

#if defined(AT_SYSINFO_EHDR)
struct vm_area_struct gate_vma;

static int __init gate_vma_init(void)
{
	gate_vma.vm_mm = NULL;
	gate_vma.vm_start = FIXADDR_USER_START;
	gate_vma.vm_end = FIXADDR_USER_END;
	gate_vma.vm_page_prot = PAGE_READONLY;
	gate_vma.vm_flags = 0;
	return 0;
}
__initcall(gate_vma_init);
#endif

struct vm_area_struct *get_gate_vma(struct task_struct *tsk)
{
#ifdef AT_SYSINFO_EHDR
	return &gate_vma;
#else
	return NULL;
#endif
}

int in_gate_area_no_task(unsigned long addr)
{
#ifdef AT_SYSINFO_EHDR
	if ((addr >= FIXADDR_USER_START) && (addr < FIXADDR_USER_END))
		return 1;
#endif
	return 0;
}

#endif	/* __HAVE_ARCH_GATE_AREA */