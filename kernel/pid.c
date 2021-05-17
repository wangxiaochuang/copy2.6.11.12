#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/hash.h>

#define pid_hashfn(nr) hash_long((unsigned long)nr, pidhash_shift)
static struct hlist_head *pid_hash[PIDTYPE_MAX];
static int pidhash_shift;

int pid_max = PID_MAX_DEFAULT;
int last_pid;

#define RESERVED_PIDS		300

#define PIDMAP_ENTRIES		((PID_MAX_LIMIT + 8*PAGE_SIZE - 1)/PAGE_SIZE/8)
#define BITS_PER_PAGE		(PAGE_SIZE*8)

typedef struct pidmap {
	atomic_t nr_free;
	void *page;
} pidmap_t;

static pidmap_t pidmap_array[PIDMAP_ENTRIES] =
	 { [ 0 ... PIDMAP_ENTRIES-1 ] = { ATOMIC_INIT(BITS_PER_PAGE), NULL } };

struct pid * fastcall find_pid(enum pid_type type, int nr)
{
	struct hlist_node *elem;
	struct pid *pid;

	hlist_for_each_entry(pid, elem,
			&pid_hash[type][pid_hashfn(nr)], pid_chain) {
        if (pid->nr == nr)
			return pid;
	}
	return NULL;
}

int fastcall attach_pid(task_t *task, enum pid_type type, int nr)
{
	struct pid *pid, *task_pid;

	task_pid = &task->pids[type];
	pid = find_pid(type, nr);
	if (pid == NULL) {
		hlist_add_head(&task_pid->pid_chain, 
				&pid_hash[type][pid_hashfn(nr)]);
		INIT_LIST_HEAD(&task_pid->pid_list);;
	} else {
		INIT_HLIST_NODE(&task_pid->pid_chain);
		list_add_tail(&task_pid->pid_list, &pid->pid_list);
	}
	task_pid->nr = nr;

	return 0;
}

/*
 * The pid hash table is scaled according to the amount of memory in the
 * machine.  From a minimum of 16 slots up to 4096 slots at one gigabyte or
 * more.
 */
void __init pidhash_init(void)
{
	int i, j, pidhash_size;
	unsigned long megabytes = nr_kernel_pages >> (20 - PAGE_SHIFT);

    pidhash_shift = max(4, fls(megabytes * 4));
	pidhash_shift = min(12, pidhash_shift);
	pidhash_size = 1 << pidhash_shift;

    printk("PID hash table entries: %d (order: %d, %Zd bytes)\n",
		pidhash_size, pidhash_shift,
		PIDTYPE_MAX * pidhash_size * sizeof(struct hlist_head));
    
    for (i = 0; i < PIDTYPE_MAX; i++) {
        pid_hash[i] = alloc_bootmem(pidhash_size *
					sizeof(*(pid_hash[i])));
        if (!pid_hash[i])
			panic("Could not alloc pidhash!\n");
		for (j = 0; j < pidhash_size; j++)
			INIT_HLIST_HEAD(&pid_hash[i][j]);
    }
}

void __init pidmap_init(void) {
	int i;

	pidmap_array->page = (void *)get_zeroed_page(GFP_KERNEL);
	set_bit(0, pidmap_array->page);
	atomic_dec(&pidmap_array->nr_free);

	for (i = 0; i < PIDTYPE_MAX; i++) 
		attach_pid(current, i, 0);
}