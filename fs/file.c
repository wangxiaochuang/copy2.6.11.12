#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/bitops.h>

struct file ** alloc_fd_array(int num)
{
	struct file **new_fds;
	int size = num * sizeof(struct file *);

	if (size <= PAGE_SIZE)
		new_fds = (struct file **) kmalloc(size, GFP_KERNEL);
	else
		new_fds = (struct file **) vmalloc(size);
	return new_fds;
}

void free_fd_array(struct file **array, int num)
{
    int size = num * sizeof(struct file *);

	if (!array) {
		printk (KERN_ERR "free_fd_array: array = 0 (num = %d)\n", num);
		return;
	}

	if (num <= NR_OPEN_DEFAULT)
		return;
	else if (size <= PAGE_SIZE)
		kfree(array);
	else
		vfree(array);
}

static int expand_fd_array(struct files_struct *files, int nr)
	__releases(files->file_lock)
	__acquires(files->file_lock)
{
	struct file **new_fds;
	int error, nfds;

	error = -EMFILE;
	if (files->max_fds >= NR_OPEN || nr >= NR_OPEN)
		goto out;

	nfds = files->max_fds;
	spin_unlock(&files->file_lock);

	do {
#if NR_OPEN_DEFAULT < 256
		if (nfds < 256)
			nfds = 256;
#endif
		if (nfds < (PAGE_SIZE / sizeof(struct file *)))
			nfds = PAGE_SIZE / sizeof(struct file *);
		else {
			nfds = nfds * 2;
			if (nfds > NR_OPEN)
				nfds = NR_OPEN;
		}
	} while (nfds <= nr);

	error = -ENOMEM;
	new_fds = alloc_fd_array(nfds);
	spin_lock(&files->file_lock);
	if (!new_fds)
		goto out;

	if (nfds > files->max_fds) {
		struct file **old_fds;
		int i;

		old_fds = xchg(&files->fd, new_fds);
		i = xchg(&files->max_fds, nfds);

		if (i) {
			memcpy(new_fds, old_fds, i * sizeof(struct file *));
			memset(&new_fds[i], 0, (nfds-i)*sizeof(struct file *));

			spin_unlock(&files->file_lock);
			free_fd_array(old_fds, i);
			spin_lock(&files->file_lock);
		}
	} else {
		/* Somebody expanded the array while we slept ... */
		spin_unlock(&files->file_lock);
		free_fd_array(new_fds, nfds);
		spin_lock(&files->file_lock);
	}
	error = 0;
out:
	return error;
}

fd_set * alloc_fdset(int num)
{
	fd_set *new_fdset;
	int size = num / 8;
	if (size <= PAGE_SIZE)
		new_fdset = (fd_set *) kmalloc(size, GFP_KERNEL);
	else
		new_fdset = (fd_set *) vmalloc(size);
	return new_fdset;
}

void free_fdset(fd_set *array, int num)
{
	int size = num / 8;

	if (num <= __FD_SETSIZE) /* Don't free an embedded fdset */
		return;
	else if (size <= PAGE_SIZE)
		kfree(array);
	else
		vfree(array);
}

static int expand_fdset(struct files_struct *files, int nr)
	__releases(file->file_lock)
	__acquires(file->file_lock)
{
	fd_set *new_openset = NULL, *new_execset = NULL;
	int error, nfds = 0;

	error = -EMFILE;
	if (files->max_fdset >= NR_OPEN || nr >= NR_OPEN)
		goto out;

	nfds = files->max_fdset;
	spin_unlock(&files->file_lock);

	do {
		if (nfds < (PAGE_SIZE * 8))
			nfds = PAGE_SIZE * 8;
		else {
			nfds = nfds * 2;
			if (nfds > NR_OPEN)
				nfds = NR_OPEN;
		}
	} while (nfds <= nr);

	error = -ENOMEM;
	new_openset = alloc_fdset(nfds);
	new_execset = alloc_fdset(nfds);
	spin_lock(&files->file_lock);
	if (!new_openset || !new_execset)
		goto out;

	error = 0;

	if (nfds > files->max_fdset) {
		int i = files->max_fdset / (sizeof(unsigned long) * 8);
		int count = (nfds - files->max_fdset) / 8;

		if (i) {
			memcpy(new_openset, files->open_fds, files->max_fdset / 8);
			memcpy(new_execset, files->close_on_exec, files->max_fdset / 8);
			memset(&new_openset->fds_bits[i], 0, count);
			memset(&new_execset->fds_bits[i], 0, count);
		}

		nfds = xchg(&files->max_fdset, nfds);
		new_openset = xchg(&files->open_fds, new_openset);
		new_execset = xchg(&files->close_on_exec, new_execset);
		spin_unlock(&files->file_lock);
		free_fdset(new_openset, nfds);
		free_fdset(new_execset, nfds);
		spin_lock(&files->file_lock);
		return 0;
	}

out:
	spin_unlock(&files->file_lock);
	if (new_openset)
		free_fdset(new_openset, nfds);
	if (new_execset)
		free_fdset(new_execset, nfds);
	spin_lock(&files->file_lock);
	return error;
}

int expand_files(struct files_struct *files, int nr)
{
	int err, expand = 0;

	if (nr >= files->max_fdset) {
		expand = 1;
		if ((err = expand_fdset(files, nr)))
			goto out;
	}
	if (nr >= files->max_fds) {
		expand = 1;
		if ((err = expand_fd_array(files, nr)))
			goto out;
	}
	err = expand;
out:
	return err;
}