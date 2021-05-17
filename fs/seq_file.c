#include <linux/fs.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include <asm/uaccess.h>
#include <asm/page.h>

int seq_open(struct file *file, struct seq_operations *op)
{
    return 0;
}

EXPORT_SYMBOL(seq_open);

ssize_t seq_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
    return 0;
}

EXPORT_SYMBOL(seq_read);

loff_t seq_lseek(struct file *file, loff_t offset, int origin)
{
    return 0;
}

EXPORT_SYMBOL(seq_lseek);

int seq_release(struct inode *inode, struct file *file)
{
    return 0;
}

EXPORT_SYMBOL(seq_release);

int seq_escape(struct seq_file *m, const char *s, const char *esc)
{
    panic("in seq_escape function");
    return 0;
}

EXPORT_SYMBOL(seq_escape);

int seq_printf(struct seq_file *m, const char *f, ...)
{
	va_list args;
	int len;

	if (m->count < m->size) {
		va_start(args, f);
		len = vsnprintf(m->buf + m->count, m->size - m->count, f, args);
		va_end(args);
		if (m->count + len < m->size) {
			m->count += len;
			return 0;
		}
	}
	m->count = m->size;
	return -1;
}
EXPORT_SYMBOL(seq_printf);

int seq_path(struct seq_file *m,
	     struct vfsmount *mnt, struct dentry *dentry,
	     char *esc)
{
    return 0;
}

EXPORT_SYMBOL(seq_path);

static void *single_start(struct seq_file *p, loff_t *pos)
{
	return NULL + (*pos == 0);
}

static void *single_next(struct seq_file *p, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void single_stop(struct seq_file *p, void *v)
{
}

int single_open(struct file *file, int (*show)(struct seq_file *, void *),
		void *data)
{
	struct seq_operations *op = kmalloc(sizeof(*op), GFP_KERNEL);
	int res = -ENOMEM;

	if (op) {
		op->start = single_start;
		op->next = single_next;
		op->stop = single_stop;
		op->show = show;
		res = seq_open(file, op);
		if (!res)
			((struct seq_file *)file->private_data)->private = data;
		else
			kfree(op);
	}
	return res;
}
EXPORT_SYMBOL(single_open);

int single_release(struct inode *inode, struct file *file)
{
	struct seq_operations *op = ((struct seq_file *)file->private_data)->op;
	int res = seq_release(inode, file);
	kfree(op);
	return res;
}
EXPORT_SYMBOL(single_release);

int seq_release_private(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;

	kfree(seq->private);
	seq->private = NULL;
	return seq_release(inode, file);
}
EXPORT_SYMBOL(seq_release_private);

int seq_putc(struct seq_file *m, char c)
{
	if (m->count < m->size) {
		m->buf[m->count++] = c;
		return 0;
	}
	return -1;
}
EXPORT_SYMBOL(seq_putc);

int seq_puts(struct seq_file *m, const char *s)
{
	int len = strlen(s);
	if (m->count + len < m->size) {
		memcpy(m->buf + m->count, s, len);
		m->count += len;
		return 0;
	}
	m->count = m->size;
	return -1;
}
EXPORT_SYMBOL(seq_puts);