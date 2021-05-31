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

EXPORT_SYMBOL(__vm_enough_memory);

static void __remove_shared_vm_struct(struct vm_area_struct *vma,
		struct file *file, struct address_space *mapping)
{
	if (vma->vm_flags & VM_DENYWRITE)
		atomic_inc(&file->f_dentry->d_inode->i_writecount);
	if (vma->vm_flags & VM_SHARED)
		mapping->i_mmap_writable--;

	flush_dcache_mmap_lock(mapping);
	if (unlikely(vma->vm_flags & VM_NONLINEAR))
		list_del_init(&vma->shared.vm_set.list);
	else
		vma_prio_tree_remove(vma, &mapping->i_mmap);
	flush_dcache_mmap_unlock(mapping);
}

#ifdef DEBUG_MM_RB
#else
#define validate_mm(mm) do { } while (0)
#endif

static struct vm_area_struct *
find_vma_prepare(struct mm_struct *mm, unsigned long addr,
		struct vm_area_struct **pprev, struct rb_node ***rb_link,
		struct rb_node ** rb_parent)
{
	struct vm_area_struct * vma;
	struct rb_node ** __rb_link, * __rb_parent, * rb_prev;

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;
	vma = NULL;

	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

		if (vma_tmp->vm_end > addr) {
			vma = vma_tmp;
			if (vma_tmp->vm_start <= addr)
				return vma;
			__rb_link = &__rb_parent->rb_left;
		} else {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

	*pprev = NULL;
	if (rb_prev)
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
	return vma;
}

static inline void
__vma_link_list(struct mm_struct *mm, struct vm_area_struct *vma,
		struct vm_area_struct *prev, struct rb_node *rb_parent)
{
	if (prev) {
		vma->vm_next = prev->vm_next;
		prev->vm_next = vma;
	} else {
		mm->mmap = vma;
		if (rb_parent)
			vma->vm_next = rb_entry(rb_parent,
					struct vm_area_struct, vm_rb);
		else
			vma->vm_next = NULL;
	}
}

void __vma_link_rb(struct mm_struct *mm, struct vm_area_struct *vma,
		struct rb_node **rb_link, struct rb_node *rb_parent)
{
	rb_link_node(&vma->vm_rb, rb_parent, rb_link);
	rb_insert_color(&vma->vm_rb, &mm->mm_rb);
}

static inline void __vma_link_file(struct vm_area_struct *vma)
{
	struct file * file;

	file = vma->vm_file;
	if (file) {
		struct address_space *mapping = file->f_mapping;

		if (vma->vm_flags & VM_DENYWRITE)
			atomic_dec(&file->f_dentry->d_inode->i_writecount);
		if (vma->vm_flags & VM_SHARED)
			mapping->i_mmap_writable++;

		flush_dcache_mmap_lock(mapping);
		if (unlikely(vma->vm_flags & VM_NONLINEAR))
			vma_nonlinear_insert(vma, &mapping->i_mmap_nonlinear);
		else
			vma_prio_tree_insert(vma, &mapping->i_mmap);
		flush_dcache_mmap_unlock(mapping);
	}
}

static void
__vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, struct rb_node **rb_link,
	struct rb_node *rb_parent)
{
	__vma_link_list(mm, vma, prev, rb_parent);
	__vma_link_rb(mm, vma, rb_link, rb_parent);
	__anon_vma_link(vma);
}

static void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
			struct vm_area_struct *prev, struct rb_node **rb_link,
			struct rb_node *rb_parent)
{
	struct address_space *mapping = NULL;

	if (vma->vm_file)
		mapping = vma->vm_file->f_mapping;

	if (mapping) {
		spin_lock(&mapping->i_mmap_lock);
		vma->vm_truncate_count = mapping->truncate_count;
	}
	anon_vma_lock(vma);

	__vma_link(mm, vma, prev, rb_link, rb_parent);
	__vma_link_file(vma);

	anon_vma_unlock(vma);
	if (mapping)
		spin_unlock(&mapping->i_mmap_lock);

	mm->map_count++;
	validate_mm(mm);
}

static void
__insert_vm_struct(struct mm_struct * mm, struct vm_area_struct * vma)
{
	struct vm_area_struct * __vma, * prev;
	struct rb_node ** rb_link, * rb_parent;

	__vma = find_vma_prepare(mm, vma->vm_start,&prev, &rb_link, &rb_parent);
	if (__vma && __vma->vm_start < vma->vm_end)
		BUG();
	__vma_link(mm, vma, prev, rb_link, rb_parent);
	mm->map_count++;
}

static inline void
__vma_unlink(struct mm_struct *mm, struct vm_area_struct *vma,
		struct vm_area_struct *prev)
{
	prev->vm_next = vma->vm_next;
	rb_erase(&vma->vm_rb, &mm->mm_rb);
	if (mm->mmap_cache == vma)
		mm->mmap_cache = prev;
}

void vma_adjust(struct vm_area_struct *vma, unsigned long start,
	unsigned long end, pgoff_t pgoff, struct vm_area_struct *insert)
{
    struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *next = vma->vm_next;
	struct vm_area_struct *importer = NULL;
	struct address_space *mapping = NULL;
	struct prio_tree_root *root = NULL;
	struct file *file = vma->vm_file;
	struct anon_vma *anon_vma = NULL;
	long adjust_next = 0;
	int remove_next = 0;

	if (next && !insert) {
		if (end >= next->vm_end) {
			/*
			 * vma expands, overlapping all the next, and
			 * perhaps the one after too (mprotect case 6).
			 */
again:			remove_next = 1 + (end > next->vm_end);
			end = next->vm_end;
			anon_vma = next->anon_vma;
			importer = vma;
		} else if (end > next->vm_start) {
			/*
			 * vma expands, overlapping part of the next:
			 * mprotect case 5 shifting the boundary up.
			 */
			adjust_next = (end - next->vm_start) >> PAGE_SHIFT;
			anon_vma = next->anon_vma;
			importer = vma;
		} else if (end < vma->vm_end) {
			/*
			 * vma shrinks, and !insert tells it's not
			 * split_vma inserting another: so it must be
			 * mprotect case 4 shifting the boundary down.
			 */
			adjust_next = - ((vma->vm_end - end) >> PAGE_SHIFT);
			anon_vma = next->anon_vma;
			importer = next;
		}
	}

	if (file) {
		mapping = file->f_mapping;
		if (!(vma->vm_flags & VM_NONLINEAR))
			root = &mapping->i_mmap;
		spin_lock(&mapping->i_mmap_lock);
		if (importer &&
		    vma->vm_truncate_count != next->vm_truncate_count) {
			/*
			 * unmap_mapping_range might be in progress:
			 * ensure that the expanding vma is rescanned.
			 */
			importer->vm_truncate_count = 0;
		}
		if (insert) {
			insert->vm_truncate_count = vma->vm_truncate_count;
			/*
			 * Put into prio_tree now, so instantiated pages
			 * are visible to arm/parisc __flush_dcache_page
			 * throughout; but we cannot insert into address
			 * space until vma start or end is updated.
			 */
			__vma_link_file(insert);
		}
	}

	/*
	 * When changing only vma->vm_end, we don't really need
	 * anon_vma lock: but is that case worth optimizing out?
	 */
	if (vma->anon_vma)
		anon_vma = vma->anon_vma;
	if (anon_vma) {
		spin_lock(&anon_vma->lock);
		/*
		 * Easily overlooked: when mprotect shifts the boundary,
		 * make sure the expanding vma has anon_vma set if the
		 * shrinking vma had, to cover any anon pages imported.
		 */
		if (importer && !importer->anon_vma) {
			importer->anon_vma = anon_vma;
			__anon_vma_link(importer);
		}
	}

	if (root) {
		flush_dcache_mmap_lock(mapping);
		vma_prio_tree_remove(vma, root);
		if (adjust_next)
			vma_prio_tree_remove(next, root);
	}

	vma->vm_start = start;
	vma->vm_end = end;
	vma->vm_pgoff = pgoff;
	if (adjust_next) {
		next->vm_start += adjust_next << PAGE_SHIFT;
		next->vm_pgoff += adjust_next;
	}

	if (root) {
		if (adjust_next)
			vma_prio_tree_insert(next, root);
		vma_prio_tree_insert(vma, root);
		flush_dcache_mmap_unlock(mapping);
	}

	if (remove_next) {
		/*
		 * vma_merge has merged next into vma, and needs
		 * us to remove next before dropping the locks.
		 */
		__vma_unlink(mm, next, vma);
		if (file)
			__remove_shared_vm_struct(next, file, mapping);
		if (next->anon_vma)
			__anon_vma_merge(vma, next);
	} else if (insert) {
		/*
		 * split_vma has split insert from vma, and needs
		 * us to insert it before dropping the locks
		 * (it may either follow vma or precede it).
		 */
		__insert_vm_struct(mm, insert);
	}

	if (anon_vma)
		spin_unlock(&anon_vma->lock);
	if (mapping)
		spin_unlock(&mapping->i_mmap_lock);

	if (remove_next) {
		if (file)
			fput(file);
		mm->map_count--;
		mpol_free(vma_policy(next));
		kmem_cache_free(vm_area_cachep, next);
		/*
		 * In mprotect's case 6 (see comments on vma_merge),
		 * we must remove another next too. It would clutter
		 * up the code too much to do both in one go.
		 */
		if (remove_next == 2) {
			next = vma->vm_next;
			goto again;
		}
	}

	validate_mm(mm);
}

/*
 * If the vma has a ->close operation then the driver probably needs to release
 * per-vma resources, so we don't attempt to merge those.
 */
#define VM_SPECIAL (VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_RESERVED)

static inline int is_mergeable_vma(struct vm_area_struct *vma,
			struct file *file, unsigned long vm_flags)
{
	if (vma->vm_flags != vm_flags)
		return 0;
	if (vma->vm_file != file)
		return 0;
	if (vma->vm_ops && vma->vm_ops->close)
		return 0;
	return 1;
}

static inline int is_mergeable_anon_vma(struct anon_vma *anon_vma1,
					struct anon_vma *anon_vma2)
{
	return !anon_vma1 || !anon_vma2 || (anon_vma1 == anon_vma2);
}

static int
can_vma_merge_before(struct vm_area_struct *vma, unsigned long vm_flags,
	struct anon_vma *anon_vma, struct file *file, pgoff_t vm_pgoff)
{
	if (is_mergeable_vma(vma, file, vm_flags) &&
	    is_mergeable_anon_vma(anon_vma, vma->anon_vma)) {
		if (vma->vm_pgoff == vm_pgoff)
			return 1;
	}
	return 0;
}

static int
can_vma_merge_after(struct vm_area_struct *vma, unsigned long vm_flags,
	struct anon_vma *anon_vma, struct file *file, pgoff_t vm_pgoff)
{
	if (is_mergeable_vma(vma, file, vm_flags) &&
	    is_mergeable_anon_vma(anon_vma, vma->anon_vma)) {
		pgoff_t vm_pglen;
		vm_pglen = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
		if (vma->vm_pgoff + vm_pglen == vm_pgoff)
			return 1;
	}
	return 0;
}

struct vm_area_struct *vma_merge(struct mm_struct *mm,
			struct vm_area_struct *prev, unsigned long addr,
			unsigned long end, unsigned long vm_flags,
		     	struct anon_vma *anon_vma, struct file *file,
			pgoff_t pgoff, struct mempolicy *policy)
{
    pgoff_t pglen = (end - addr) >> PAGE_SHIFT;
	struct vm_area_struct *area, *next;

    if (vm_flags & VM_SPECIAL)
		return NULL;

    if (prev)
		next = prev->vm_next;
	else
		next = mm->mmap;
	area = next;
	if (next && next->vm_end == end)		/* cases 6, 7, 8 */
		next = next->vm_next;
    
    /*
	 * Can it merge with the predecessor?
	 */
	if (prev && prev->vm_end == addr &&
  			mpol_equal(vma_policy(prev), policy) &&
			can_vma_merge_after(prev, vm_flags,
						anon_vma, file, pgoff)) {
		/*
		 * OK, it can.  Can we now merge in the successor as well?
		 */
		if (next && end == next->vm_start &&
				mpol_equal(policy, vma_policy(next)) &&
				can_vma_merge_before(next, vm_flags,
					anon_vma, file, pgoff+pglen) &&
				is_mergeable_anon_vma(prev->anon_vma,
						      next->anon_vma)) {
							/* cases 1, 6 */
			vma_adjust(prev, prev->vm_start,
				next->vm_end, prev->vm_pgoff, NULL);
		} else					/* cases 2, 5, 7 */
			vma_adjust(prev, prev->vm_start,
				end, prev->vm_pgoff, NULL);
		return prev;
	}

    /*
	 * Can this new request be merged in front of next?
	 */
	if (next && end == next->vm_start &&
 			mpol_equal(policy, vma_policy(next)) &&
			can_vma_merge_before(next, vm_flags,
					anon_vma, file, pgoff+pglen)) {
		if (prev && addr < prev->vm_end)	/* case 4 */
			vma_adjust(prev, prev->vm_start,
				addr, prev->vm_pgoff, NULL);
		else					/* cases 3, 8 */
			vma_adjust(area, addr, next->vm_end,
				next->vm_pgoff - pglen, NULL);
		return area;
	}

	return NULL;
}

struct anon_vma *find_mergeable_anon_vma(struct vm_area_struct *vma)
{
	struct vm_area_struct *near;
	unsigned long vm_flags;

	near = vma->vm_next;
	if (!near)
		goto try_prev;
    
    vm_flags = vma->vm_flags & ~(VM_READ|VM_WRITE|VM_EXEC);
	vm_flags |= near->vm_flags & (VM_READ|VM_WRITE|VM_EXEC);

    if (near->anon_vma && vma->vm_end == near->vm_start &&
            mpol_equal(vma_policy(vma), vma_policy(near)) &&
            can_vma_merge_before(near, vm_flags,
                NULL, vma->vm_file, vma->vm_pgoff +
                ((vma->vm_end - vma->vm_start) >> PAGE_SHIFT)))
        return near->anon_vma;
try_prev:
    if (find_vma_prev(vma->vm_mm, vma->vm_start, &near) != vma)
		BUG();
	if (!near)
		goto none;
    
    vm_flags = vma->vm_flags & ~(VM_READ|VM_WRITE|VM_EXEC);
	vm_flags |= near->vm_flags & (VM_READ|VM_WRITE|VM_EXEC);

    if (near->anon_vma && near->vm_end == vma->vm_start &&
  			mpol_equal(vma_policy(near), vma_policy(vma)) &&
			can_vma_merge_after(near, vm_flags,
				NULL, vma->vm_file, vma->vm_pgoff))
		return near->anon_vma;
none:
    return NULL;
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

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
struct vm_area_struct * find_vma(struct mm_struct * mm, unsigned long addr)
{
	struct vm_area_struct *vma = NULL;

    if (mm) {
        vma = mm->mmap_cache;
        if (!(vma && vma->vm_end > addr && vma->vm_start <= addr)) {
            struct rb_node * rb_node;

			rb_node = mm->mm_rb.rb_node;
			vma = NULL;

            while (rb_node) {
                struct vm_area_struct * vma_tmp;

				vma_tmp = rb_entry(rb_node,
						struct vm_area_struct, vm_rb);

				if (vma_tmp->vm_end > addr) {
					vma = vma_tmp;
					if (vma_tmp->vm_start <= addr)
						break;
					rb_node = rb_node->rb_left;
				} else
					rb_node = rb_node->rb_right;
            }
            if (vma)
				mm->mmap_cache = vma;
        }
    }
    return vma;
}

EXPORT_SYMBOL(find_vma);

/* Same as find_vma, but also return a pointer to the previous VMA in *pprev. */
struct vm_area_struct *
find_vma_prev(struct mm_struct *mm, unsigned long addr,
			struct vm_area_struct **pprev)
{
	struct vm_area_struct *vma = NULL, *prev = NULL;
	struct rb_node * rb_node;
	if (!mm)
		goto out;

	/* Guard against addr being lower than the first VMA */
	vma = mm->mmap;

	/* Go through the RB tree quickly. */
	rb_node = mm->mm_rb.rb_node;

	while (rb_node) {
		struct vm_area_struct *vma_tmp;
		vma_tmp = rb_entry(rb_node, struct vm_area_struct, vm_rb);

		if (addr < vma_tmp->vm_end) {
			rb_node = rb_node->rb_left;
		} else {
			prev = vma_tmp;
			if (!prev->vm_next || (addr < prev->vm_next->vm_end))
				break;
			rb_node = rb_node->rb_right;
		}
	}

out:
	*pprev = prev;
	return prev ? prev->vm_next : vma;
}

/*
 * Verify that the stack growth is acceptable and
 * update accounting. This is shared with both the
 * grow-up and grow-down cases.
 */
static int acct_stack_growth(struct vm_area_struct * vma, unsigned long size, unsigned long grow)
{
	struct mm_struct *mm = vma->vm_mm;
	struct rlimit *rlim = current->signal->rlim;

	/* address space limit tests */
	if (mm->total_vm + grow > rlim[RLIMIT_AS].rlim_cur >> PAGE_SHIFT)
		return -ENOMEM;

	/* Stack limit test */
	if (size > rlim[RLIMIT_STACK].rlim_cur)
		return -ENOMEM;

	/* mlock limit tests */
	if (vma->vm_flags & VM_LOCKED) {
		unsigned long locked;
		unsigned long limit;
		locked = mm->locked_vm + grow;
		limit = rlim[RLIMIT_MEMLOCK].rlim_cur >> PAGE_SHIFT;
		if (locked > limit && !capable(CAP_IPC_LOCK))
			return -ENOMEM;
	}

	/*
	 * Overcommit..  This must be the final test, as it will
	 * update security statistics.
	 */
	if (security_vm_enough_memory(grow))
		return -ENOMEM;

	/* Ok, everything looks good - let it rip */
	mm->total_vm += grow;
	if (vma->vm_flags & VM_LOCKED)
		mm->locked_vm += grow;
	__vm_stat_account(mm, vma->vm_flags, vma->vm_file, grow);
	acct_update_integrals();
	update_mem_hiwater();
	return 0;
}

#ifdef CONFIG_STACK_GROWSUP
#else
int expand_stack(struct vm_area_struct *vma, unsigned long address)
{
    int error;

    if (unlikely(anon_vma_prepare(vma)))
        return -ENOMEM;
    anon_vma_lock(vma);

    address &= PAGE_MASK;
	error = 0;

    /* Somebody else might have raced and expanded it already */
	if (address < vma->vm_start) {
		unsigned long size, grow;

		size = vma->vm_end - address;
		grow = (vma->vm_start - address) >> PAGE_SHIFT;

		error = acct_stack_growth(vma, size, grow);
		if (!error) {
			vma->vm_start = address;
			vma->vm_pgoff -= grow;
		}
	}
	anon_vma_unlock(vma);
	return error;    
}

struct vm_area_struct *
find_extend_vma(struct mm_struct * mm, unsigned long addr)
{
	struct vm_area_struct * vma;
	unsigned long start;

	addr &= PAGE_MASK;
	vma = find_vma(mm,addr);
	if (!vma)
		return NULL;
	if (vma->vm_start <= addr)
		return vma;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		return NULL;
	start = vma->vm_start;
	if (expand_stack(vma, addr))
		return NULL;
	if (vma->vm_flags & VM_LOCKED) {
		make_pages_present(addr, start);
	}
	return vma;
}
#endif