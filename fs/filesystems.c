#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/uaccess.h>

void get_filesystem(struct file_system_type *fs);
void put_filesystem(struct file_system_type *fs);
struct file_system_type *get_fs_type(const char *name);

static struct file_system_type *file_systems;
static DEFINE_RWLOCK(file_systems_lock);

void get_filesystem(struct file_system_type *fs)
{
	__module_get(fs->owner);
}

void put_filesystem(struct file_system_type *fs)
{
	module_put(fs->owner);
}

static struct file_system_type **find_filesystem(const char *name)
{
	struct file_system_type **p;
    for (p = &file_systems; *p; p = &(*p)->next)
        if (strcmp((*p)->name, name) == 0)
            break;
    return p;
}

int register_filesystem(struct file_system_type * fs)
{
    int res = 0;
    struct file_system_type ** p;

    if (!fs)
		return -EINVAL;
	if (fs->next)
		return -EBUSY;
    INIT_LIST_HEAD(&fs->fs_supers);
	write_lock(&file_systems_lock);
    p = find_filesystem(fs->name);
	if (*p)
		res = -EBUSY;
	else
		*p = fs;
	write_unlock(&file_systems_lock);
    return res;
}

EXPORT_SYMBOL(register_filesystem);

int unregister_filesystem(struct file_system_type * fs)
{
    struct file_system_type ** tmp;

	write_lock(&file_systems_lock);
	tmp = &file_systems;
	while (*tmp) {
		if (fs == *tmp) {
			*tmp = fs->next;
			fs->next = NULL;
			write_unlock(&file_systems_lock);
			return 0;
		}
		tmp = &(*tmp)->next;
	}
	write_unlock(&file_systems_lock);
	return -EINVAL;
}

EXPORT_SYMBOL(unregister_filesystem);

struct file_system_type *get_fs_type(const char *name)
{
	struct file_system_type *fs;

    read_lock(&file_systems_lock);
    fs = *(find_filesystem(name));
    if (fs && !try_module_get(fs->owner))
        fs = NULL;
    read_unlock(&file_systems_lock);
    if (!fs && (request_module("%s", name) == 0)) {
        read_lock(&file_systems_lock);
        if (fs && !try_module_get(fs->owner))
			fs = NULL;
        read_unlock(&file_systems_lock);
    }
    return fs;
}

EXPORT_SYMBOL(get_fs_type);