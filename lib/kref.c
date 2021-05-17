#include <linux/kref.h>
#include <linux/module.h>

void kref_init(struct kref *kref)
{
	atomic_set(&kref->refcount,1);
}

void kref_get(struct kref *kref)
{
	WARN_ON(!atomic_read(&kref->refcount));
	atomic_inc(&kref->refcount);
}

void kref_put(struct kref *kref, void (*release) (struct kref *kref))
{
	WARN_ON(release == NULL);
	WARN_ON(release == (void (*)(struct kref *))kfree);

	if (atomic_dec_and_test(&kref->refcount))
		release(kref);
}

EXPORT_SYMBOL(kref_init);
EXPORT_SYMBOL(kref_get);
EXPORT_SYMBOL(kref_put);