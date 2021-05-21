#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/profile.h>
#include <linux/module.h>
#include <linux/acct.h>
#include <linux/mount.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>

#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlb.h>

int sysctl_overcommit_memory = OVERCOMMIT_GUESS;  /* heuristic overcommit */
int sysctl_overcommit_ratio = 50;	/* default is 50% */
int sysctl_max_map_count = DEFAULT_MAX_MAP_COUNT;
atomic_t vm_committed_space = ATOMIC_INIT(0);

int __vm_enough_memory(long pages, int cap_sys_admin)
{
    unsigned long free, allowed;

	vm_acct_memory(pages);

    if (sysctl_overcommit_memory == OVERCOMMIT_ALWAYS)
        return 0;
    if (sysctl_overcommit_memory == OVERCOMMIT_GUESS) {
        unsigned long n;
        free = get_page_cache_size();
        free += nr_swap_pages;

        free += atomic_read(&slab_reclaim_pages);

        if (!cap_sys_admin)
            free -= free / 32;
        
        if (free > pages)
            return 0;
        
        n = nr_free_pages();
        if (!cap_sys_admin)
            n -= n / 32;
        free += n;

        if (free > pages)
            return 0;
        vm_unacct_memory(pages);
        return -ENOMEM;
    }

    allowed = (totalram_pages - hugetlb_total_pages())
            * sysctl_overcommit_ratio / 100;
    
    if (!cap_sys_admin)
        allowed -= allowed / 32;
    allowed += total_swap_pages;

    allowed -= current->mm->total_vm / 32;

    if (atomic_read(&vm_committed_space) < allowed)
        return 0;
    
    vm_unacct_memory(pages);

    return -ENOMEM;
}




void __vma_link_rb(struct mm_struct *mm, struct vm_area_struct *vma,
		struct rb_node **rb_link, struct rb_node *rb_parent)
{
	rb_link_node(&vma->vm_rb, rb_parent, rb_link);
	rb_insert_color(&vma->vm_rb, &mm->mm_rb);
}




#ifdef CONFIG_PROC_FS
void __vm_stat_account(struct mm_struct *mm, unsigned long flags,
						struct file *file, long pages)
{
    const unsigned long stack_flags
        = VM_STACK_FLAGS & (VM_GROWSUP | VM_GROWSDOWN);
#ifdef CONFIG_HUGETLB
#error "CONFIG_HUGETLB"
#endif
    if (file) {
        mm->shared_vm += pages;
        if ((flags & (VM_EXEC|VM_WRITE)) == VM_EXEC)
            mm->exec_vm += pages;
    } else if (flags & stack_flags)
        mm->stack_vm += pages;
    if (flags & (VM_RESERVED|VM_IO))
        mm->reserved_vm += pages;
}
#endif /* CONFIG_PROC_FS */