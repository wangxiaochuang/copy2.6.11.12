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

/* Return the number pages of memory we physically have, in PAGE_SIZE units. */
unsigned long hugetlb_total_pages(void)
{
	return nr_huge_pages * (HPAGE_SIZE / PAGE_SIZE);
}
EXPORT_SYMBOL(hugetlb_total_pages);