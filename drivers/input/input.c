#include <linux/init.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/input.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/major.h>
#include <linux/proc_fs.h>
#include <linux/kobject_uevent.h>
#include <linux/interrupt.h>
#include <linux/poll.h>
#include <linux/device.h>
#include <linux/devfs_fs_kernel.h>

MODULE_AUTHOR("Vojtech Pavlik <vojtech@suse.cz>");
MODULE_DESCRIPTION("Input core");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(input_register_device);
EXPORT_SYMBOL(input_unregister_device);
EXPORT_SYMBOL(input_register_handler);
EXPORT_SYMBOL(input_unregister_handler);
EXPORT_SYMBOL(input_grab_device);
EXPORT_SYMBOL(input_release_device);
EXPORT_SYMBOL(input_open_device);
EXPORT_SYMBOL(input_close_device);
EXPORT_SYMBOL(input_accept_process);
EXPORT_SYMBOL(input_flush_device);
EXPORT_SYMBOL(input_event);
EXPORT_SYMBOL(input_class);

#define INPUT_DEVICES	256

static LIST_HEAD(input_dev_list);
static LIST_HEAD(input_handler_list);

static struct input_handler *input_table[8];

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *proc_bus_input_dir;
DECLARE_WAIT_QUEUE_HEAD(input_devices_poll_wait);
static int input_devices_state;
#endif

static inline unsigned int ms_to_jiffies(unsigned int ms)
{
        unsigned int j;
        j = (ms * HZ + 500) / 1000;
        return (j > 0) ? j : 1;
}

void input_event(struct input_dev *dev, unsigned int type, unsigned int code, int value)
{
	panic("in input_event");
}

static void input_repeat_key(unsigned long data)
{
	panic("in input_repeat_key");
}

int input_accept_process(struct input_handle *handle, struct file *file)
{
	if (handle->dev->accept)
		return handle->dev->accept(handle->dev, file);

	return 0;
}

int input_grab_device(struct input_handle *handle)
{
	if (handle->dev->grab)
		return -EBUSY;

	handle->dev->grab = handle;
	return 0;
}

void input_release_device(struct input_handle *handle)
{
	if (handle->dev->grab == handle)
		handle->dev->grab = NULL;
}

int input_open_device(struct input_handle *handle)
{
	handle->open++;
	if (handle->dev->open)
		return handle->dev->open(handle->dev);
	return 0;
}

int input_flush_device(struct input_handle* handle, struct file* file)
{
	if (handle->dev->flush)
		return handle->dev->flush(handle->dev, file);

	return 0;
}

void input_close_device(struct input_handle *handle)
{
	input_release_device(handle);
	if (handle->dev->close)
		handle->dev->close(handle->dev);
	handle->open--;
}

static void input_link_handle(struct input_handle *handle)
{
	list_add_tail(&handle->d_node, &handle->dev->h_list);
	list_add_tail(&handle->h_node, &handle->handler->h_list);
}

#define MATCH_BIT(bit, max) \
		for (i = 0; i < NBITS(max); i++) \
			if ((id->bit[i] & dev->bit[i]) != id->bit[i]) \
				break; \
		if (i != NBITS(max)) \
			continue;

static struct input_device_id *input_match_device(struct input_device_id *id, struct input_dev *dev)
{
	panic("in input_match_device");
	return NULL;
}

#ifdef CONFIG_HOTPLUG

#define SPRINTF_BIT_A(bit, name, max) \
	do { \
		envp[i++] = scratch; \
		scratch += sprintf(scratch, name); \
		for (j = NBITS(max) - 1; j >= 0; j--) \
			if (dev->bit[j]) break; \
		for (; j >= 0; j--) \
			scratch += sprintf(scratch, "%lx ", dev->bit[j]); \
		scratch++; \
	} while (0)

#define SPRINTF_BIT_A2(bit, name, max, ev) \
	do { \
		if (test_bit(ev, dev->evbit)) \
			SPRINTF_BIT_A(bit, name, max); \
	} while (0)

static void input_call_hotplug(char *verb, struct input_dev *dev)
{
	panic("in input_call_hotplug");
}

#endif

void input_register_device(struct input_dev *dev)
{
	panic("in input_register_device");
}

void input_unregister_device(struct input_dev *dev)
{
	panic("in input_unregister_device");
}


void input_register_handler(struct input_handler *handler)
{
	struct input_dev *dev;
	struct input_handle *handle;
	struct input_device_id *id;

	if (!handler) return;

	INIT_LIST_HEAD(&handler->h_list);

	if (handler->fops != NULL)
		input_table[handler->minor >> 5] = handler;

	list_add_tail(&handler->node, &input_handler_list);

	list_for_each_entry(dev, &input_dev_list, node)
		if (!handler->blacklist || !input_match_device(handler->blacklist, dev))
			if ((id = input_match_device(handler->id_table, dev)))
				if ((handle = handler->connect(handler, dev, id)))
					input_link_handle(handle);

#ifdef CONFIG_PROC_FS
	input_devices_state++;
	wake_up(&input_devices_poll_wait);
#endif
}

void input_unregister_handler(struct input_handler *handler)
{
	struct list_head * node, * next;

	list_for_each_safe(node, next, &handler->h_list) {
		struct input_handle * handle = to_handle_h(node);
		list_del_init(&handle->h_node);
		list_del_init(&handle->d_node);
		handler->disconnect(handle);
	}

	list_del_init(&handler->node);

	if (handler->fops != NULL)
		input_table[handler->minor >> 5] = NULL;

#ifdef CONFIG_PROC_FS
	input_devices_state++;
	wake_up(&input_devices_poll_wait);
#endif
}
	
static int input_open_file(struct inode *inode, struct file *file)
{
	panic("in input_open_file");
	return 0;
}

static struct file_operations input_fops = {
	.owner = THIS_MODULE,
	.open = input_open_file,
};

#ifdef CONFIG_PROC_FS

#define SPRINTF_BIT_B(bit, name, max) \
	do { \
		len += sprintf(buf + len, "B: %s", name); \
		for (i = NBITS(max) - 1; i >= 0; i--) \
			if (dev->bit[i]) break; \
		for (; i >= 0; i--) \
			len += sprintf(buf + len, "%lx ", dev->bit[i]); \
		len += sprintf(buf + len, "\n"); \
	} while (0)

#define SPRINTF_BIT_B2(bit, name, max, ev) \
	do { \
		if (test_bit(ev, dev->evbit)) \
			SPRINTF_BIT_B(bit, name, max); \
	} while (0)

static unsigned int input_devices_poll(struct file *file, poll_table *wait)
{
	panic("in input_devices_poll");
	return 0;
}

static int input_devices_read(char *buf, char **start, off_t pos, int count, int *eof, void *data)
{
	panic("in input_devices_read");
	return 0;
}

static int input_handlers_read(char *buf, char **start, off_t pos, int count, int *eof, void *data)
{
	panic("in input_handlers_read");
	return 0;
}

static int __init input_proc_init(void)
{
	struct proc_dir_entry *entry;

	proc_bus_input_dir = proc_mkdir("input", proc_bus);
	if (proc_bus_input_dir == NULL)
		return -ENOMEM;
	proc_bus_input_dir->owner = THIS_MODULE;
	entry = create_proc_read_entry("devices", 0, proc_bus_input_dir, input_devices_read, NULL);
	if (entry == NULL) {
		remove_proc_entry("input", proc_bus);
		return -ENOMEM;
	}
	entry->owner = THIS_MODULE;
	entry->proc_fops->poll = input_devices_poll;
	entry = create_proc_read_entry("handlers", 0, proc_bus_input_dir, input_handlers_read, NULL);
	if (entry == NULL) {
		remove_proc_entry("devices", proc_bus_input_dir);
		remove_proc_entry("input", proc_bus);
		return -ENOMEM;
	}
	entry->owner = THIS_MODULE;
	return 0;
}

#else /* !CONFIG_PROC_FS */
static inline int input_proc_init(void) { return 0; }
#endif

struct class_simple *input_class;

static int __init input_init(void)
{
	int retval = -ENOMEM;

	input_class = class_simple_create(THIS_MODULE, "input");
	if (IS_ERR(input_class))
		return PTR_ERR(input_class);
	input_proc_init();
	retval = register_chrdev(INPUT_MAJOR, "input", &input_fops);
	if (retval) {
		printk(KERN_ERR "input: unable to register char major %d", INPUT_MAJOR);
		remove_proc_entry("devices", proc_bus_input_dir);
		remove_proc_entry("handlers", proc_bus_input_dir);
		remove_proc_entry("input", proc_bus);
		class_simple_destroy(input_class);
		return retval;
	}

	retval = devfs_mk_dir("input");
	if (retval) {
		remove_proc_entry("devices", proc_bus_input_dir);
		remove_proc_entry("handlers", proc_bus_input_dir);
		remove_proc_entry("input", proc_bus);
		unregister_chrdev(INPUT_MAJOR, "input");
		class_simple_destroy(input_class);
	}
	return retval;
}

static void __exit input_exit(void)
{
	remove_proc_entry("devices", proc_bus_input_dir);
	remove_proc_entry("handlers", proc_bus_input_dir);
	remove_proc_entry("input", proc_bus);

	devfs_remove("input");
	unregister_chrdev(INPUT_MAJOR, "input");
	class_simple_destroy(input_class);
}

subsys_initcall(input_init);
module_exit(input_exit);