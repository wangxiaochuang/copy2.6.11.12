#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/string.h>
#include <linux/kobject_uevent.h>
#include <linux/kobject.h>
#include <net/sock.h>

#define BUFFER_SIZE	1024	/* buffer for the hotplug env */
#define NUM_ENVP	32	/* number of env pointers */

#if defined(CONFIG_KOBJECT_UEVENT) || defined(CONFIG_HOTPLUG)
static char *action_to_string(enum kobject_action action)
{
	switch (action) {
	case KOBJ_ADD:
		return "add";
	case KOBJ_REMOVE:
		return "remove";
	case KOBJ_CHANGE:
		return "change";
	case KOBJ_MOUNT:
		return "mount";
	case KOBJ_UMOUNT:
		return "umount";
	case KOBJ_OFFLINE:
		return "offline";
	case KOBJ_ONLINE:
		return "online";
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_KOBJECT_UEVENT
static struct sock *uevent_sock;

static int send_uevent(const char *signal, const char *obj,
		       char **envp, int gfp_mask)
{
    struct sk_buff *skb;
	char *pos;
	int len;

	if (!uevent_sock)
		return -EIO;
    
    panic("in send_uevent function");
    return 0;
}
#else
#endif

#ifdef CONFIG_HOTPLUG

char hotplug_path[HOTPLUG_PATH_LEN] = "/sbin/hotplug";
u64 hotplug_seqnum;
static DEFINE_SPINLOCK(sequence_lock);

void kobject_hotplug(struct kobject *kobj, enum kobject_action action)
{
    char *argv [3];
	char **envp = NULL;
	char *buffer = NULL;
	char *seq_buff;
	char *scratch;
	int i = 0;
	int retval;
	char *kobj_path = NULL;
	char *name = NULL;
	char *action_string;
	u64 seq;
	struct kobject *top_kobj = kobj;
	struct kset *kset;
	static struct kset_hotplug_ops null_hotplug_ops;
	struct kset_hotplug_ops *hotplug_ops = &null_hotplug_ops;

	/* If this kobj does not belong to a kset,
	   try to find a parent that does. */
	if (!top_kobj->kset && top_kobj->parent) {
		do {
			top_kobj = top_kobj->parent;
		} while (!top_kobj->kset && top_kobj->parent);
	}

	if (top_kobj->kset)
		kset = top_kobj->kset;
	else
		return;

	if (kset->hotplug_ops)
		hotplug_ops = kset->hotplug_ops;

	/* If the kset has a filter operation, call it.
	   Skip the event, if the filter returns zero. */
	if (hotplug_ops->filter) {
		if (!hotplug_ops->filter(kset, kobj))
			return;
	}

	pr_debug ("%s\n", __FUNCTION__);

	action_string = action_to_string(action);
	if (!action_string)
		return;

	envp = kmalloc(NUM_ENVP * sizeof (char *), GFP_KERNEL);
	if (!envp)
		return;
	memset (envp, 0x00, NUM_ENVP * sizeof (char *));

	buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
	if (!buffer)
		goto exit;

	if (hotplug_ops->name)
		name = hotplug_ops->name(kset, kobj);
	if (name == NULL)
		name = kset->kobj.name;

	argv [0] = hotplug_path;
	argv [1] = name;
	argv [2] = NULL;

	/* minimal command environment */
	envp [i++] = "HOME=/";
	envp [i++] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";

	scratch = buffer;

	envp [i++] = scratch;
	scratch += sprintf(scratch, "ACTION=%s", action_string) + 1;

	kobj_path = kobject_get_path(kobj, GFP_KERNEL);
	if (!kobj_path)
		goto exit;

	envp [i++] = scratch;
	scratch += sprintf (scratch, "DEVPATH=%s", kobj_path) + 1;

	envp [i++] = scratch;
	scratch += sprintf(scratch, "SUBSYSTEM=%s", name) + 1;

	/* reserve space for the sequence,
	 * put the real one in after the hotplug call */
	envp[i++] = seq_buff = scratch;
	scratch += strlen("SEQNUM=18446744073709551616") + 1;

	if (hotplug_ops->hotplug) {
		/* have the kset specific function add its stuff */
		retval = hotplug_ops->hotplug (kset, kobj,
				  &envp[i], NUM_ENVP - i, scratch,
				  BUFFER_SIZE - (scratch - buffer));
		if (retval) {
			pr_debug ("%s - hotplug() returned %d\n",
				  __FUNCTION__, retval);
			goto exit;
		}
	}

	spin_lock(&sequence_lock);
	seq = ++hotplug_seqnum;
	spin_unlock(&sequence_lock);
	sprintf(seq_buff, "SEQNUM=%llu", (unsigned long long)seq);

	pr_debug ("%s: %s %s seq=%llu %s %s %s %s %s\n",
		  __FUNCTION__, argv[0], argv[1], (unsigned long long)seq,
		  envp[0], envp[1], envp[2], envp[3], envp[4]);

	send_uevent(action_string, kobj_path, envp, GFP_KERNEL);

	if (!hotplug_path[0])
		goto exit;

	retval = call_usermodehelper (argv[0], argv, envp, 0);
	if (retval)
		pr_debug ("%s - call_usermodehelper returned %d\n",
			  __FUNCTION__, retval);

exit:
	kfree(kobj_path);
	kfree(buffer);
	kfree(envp);
	return;
}

EXPORT_SYMBOL(kobject_hotplug);

#endif /* CONFIG_HOTPLUG */