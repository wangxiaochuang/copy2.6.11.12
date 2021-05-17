#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/swapops.h>
#include <linux/writeback.h>
#include <asm/pgtable.h>

int swap_writepage(struct page *page, struct writeback_control *wbc)
{
    panic("in swap_writepage function");
    return 0;
}