#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/sysctl.h>
#include <linux/highmem.h>
#include <linux/nodemask.h>

static unsigned long nr_huge_pages, free_huge_pages;

int is_hugepage_mem_enough(size_t size)
{
	return (size + ~HPAGE_MASK)/HPAGE_SIZE <= free_huge_pages;
}

/* Return the number pages of memory we physically have, in PAGE_SIZE units. */
unsigned long hugetlb_total_pages(void)
{
	return nr_huge_pages * (HPAGE_SIZE / PAGE_SIZE);
}
EXPORT_SYMBOL(hugetlb_total_pages);


static struct page *hugetlb_nopage(struct vm_area_struct *vma,
				unsigned long address, int *unused)
{
	BUG();
	return NULL;
}

struct vm_operations_struct hugetlb_vm_ops = {
	.nopage = hugetlb_nopage,
};

void zap_hugepage_range(struct vm_area_struct *vma,
			unsigned long start, unsigned long length)
{
	struct mm_struct *mm = vma->vm_mm;

	spin_lock(&mm->page_table_lock);
	unmap_hugepage_range(vma, start, start + length);
	spin_unlock(&mm->page_table_lock);
}