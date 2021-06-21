#include <linux/config.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/err.h>

struct class_simple {
	struct class_device_attribute attr;
	struct class class;
};
#define to_class_simple(d) container_of(d, struct class_simple, class)

struct simple_dev {
	struct list_head node;
	dev_t dev;
	struct class_device class_dev;
};
#define to_simple_dev(d) container_of(d, struct simple_dev, class_dev)

static LIST_HEAD(simple_dev_list);
static DEFINE_SPINLOCK(simple_dev_list_lock);

static void release_simple_dev(struct class_device *class_dev)
{
	struct simple_dev *s_dev = to_simple_dev(class_dev);
	kfree(s_dev);
}

static ssize_t show_dev(struct class_device *class_dev, char *buf)
{
	struct simple_dev *s_dev = to_simple_dev(class_dev);
	return print_dev_t(buf, s_dev->dev);
}

static void class_simple_release(struct class *class)
{
	struct class_simple *cs = to_class_simple(class);
	kfree(cs);
}

struct class_simple *class_simple_create(struct module *owner, char *name)
{
	struct class_simple *cs;
	int retval;

	cs = kmalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs) {
		retval = -ENOMEM;
		goto error;
	}
	memset(cs, 0x00, sizeof(*cs));

	cs->class.name = name;
	cs->class.class_release = class_simple_release;
	cs->class.release = release_simple_dev;

	cs->attr.attr.name = "dev";
	cs->attr.attr.mode = S_IRUGO;
	cs->attr.attr.owner = owner;
	cs->attr.show = show_dev;
	cs->attr.store = NULL;

	retval = class_register(&cs->class);
	if (retval)
		goto error;

	return cs;

error:
	kfree(cs);
	return ERR_PTR(retval);
}

void class_simple_destroy(struct class_simple *cs)
{
	if ((cs == NULL) || (IS_ERR(cs)))
		return;

	class_unregister(&cs->class);
}
EXPORT_SYMBOL(class_simple_destroy);

struct class_device *class_simple_device_add(struct class_simple *cs, dev_t dev, struct device *device, const char *fmt, ...)
{
	va_list args;
	struct simple_dev *s_dev = NULL;
	int retval;

	if ((cs == NULL) || (IS_ERR(cs))) {
		retval = -ENODEV;
		goto error;
	}

	s_dev = kmalloc(sizeof(*s_dev), GFP_KERNEL);
	if (!s_dev) {
		retval = -ENOMEM;
		goto error;
	}
	memset(s_dev, 0x00, sizeof(*s_dev));

	s_dev->dev = dev;
	s_dev->class_dev.dev = device;
	s_dev->class_dev.class = &cs->class;

	va_start(args, fmt);
	vsnprintf(s_dev->class_dev.class_id, BUS_ID_SIZE, fmt, args);
	va_end(args);
	retval = class_device_register(&s_dev->class_dev);
	if (retval)
		goto error;
	
	class_device_create_file(&s_dev->class_dev, &cs->attr);

	spin_lock(&simple_dev_list_lock);
	list_add(&s_dev->node, &simple_dev_list);
	spin_unlock(&simple_dev_list_lock);

	return &s_dev->class_dev;

error:
	kfree(s_dev);
	return ERR_PTR(retval);
}

EXPORT_SYMBOL(class_simple_device_add);

int class_simple_set_hotplug(struct class_simple *cs,
	int (*hotplug)(struct class_device *dev, char **envp, int num_envp, char *buffer, int buffer_size))
{
	if ((cs == NULL) || (IS_ERR(cs)))
		return -ENODEV;
	cs->class.hotplug = hotplug;
	return 0;
}
EXPORT_SYMBOL(class_simple_set_hotplug);

void class_simple_device_remove(dev_t dev)
{
	struct simple_dev *s_dev = NULL;
	int found = 0;

	spin_lock(&simple_dev_list_lock);
	list_for_each_entry(s_dev, &simple_dev_list, node) {
		if (s_dev->dev == dev) {
			found = 1;
			break;
		}
	}
	if (found) {
		list_del(&s_dev->node);
		spin_unlock(&simple_dev_list_lock);
		class_device_unregister(&s_dev->class_dev);
	} else {
		spin_unlock(&simple_dev_list_lock);
	}
}
EXPORT_SYMBOL(class_simple_device_remove);