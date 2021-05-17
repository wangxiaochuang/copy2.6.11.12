#ifndef TEST                        // to test in user space...
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module.h>
#endif
#include <linux/string.h>
#include <linux/idr.h>

static kmem_cache_t *idr_layer_cache;

static struct idr_layer *alloc_layer(struct idr *idp)
{
	struct idr_layer *p;

	spin_lock(&idp->lock);
	if ((p = idp->id_free)) {
		idp->id_free = p->ary[0];
		idp->id_free_cnt--;
		p->ary[0] = NULL;
	}
	spin_unlock(&idp->lock);
	return(p);
}

static void free_layer(struct idr *idp, struct idr_layer *p)
{
	spin_lock(&idp->lock);
	p->ary[0] = idp->id_free;
	idp->id_free = p;
	idp->id_free_cnt++;
	spin_unlock(&idp->lock);
}

int idr_pre_get(struct idr *idp, unsigned gfp_mask)
{
	while (idp->id_free_cnt < IDR_FREE_MAX) {
		struct idr_layer *new;
		new = kmem_cache_alloc(idr_layer_cache, gfp_mask);
		if(new == NULL)
			return (0);
		free_layer(idp, new);
	}

	return 1;
}

EXPORT_SYMBOL(idr_pre_get);

static int sub_alloc(struct idr *idp, void *ptr, int *starting_id)
{
	int n, m, sh;
	struct idr_layer *p, *new;
	struct idr_layer *pa[MAX_LEVEL];
	int l, id;
	long bm;

	id = *starting_id;
	p = idp->top;
	l = idp->layers;
	pa[l--] = NULL;
	while (1) {
		n = (id >> (IDR_BITS * l)) & IDR_MASK;
		bm = ~p->bitmap;
		m = find_next_bit(&bm, IDR_SIZE, n);
		if (m == IDR_SIZE) {
			l++;
			id = (id | ((1 << (IDR_BITS * l)) - 1)) + 1;
			if (!(p = pa[l])) {
				*starting_id = id;
				return -2;
			}
			continue;
		}
		if (m != n) {
			sh = IDR_BITS * l;
			id = ((id >> sh) ^ n ^ m) << sh;
		}
		if ((id >= MAX_ID_BIT) || (id < 0))
			return -3;
		if (l == 0)
			break;

		if (!p->ary[m]) {
			if (!(new = alloc_layer(idp)))
				return -1;
			p->ary[m] = new;
			p->count++;
		}
		pa[l--] = p;
		p = p->ary[m];
	}

	p->ary[m] = (struct idr_layer *)ptr;
	__set_bit(m, &p->bitmap);
	p->count++;

	n = id;
	while (p->bitmap == IDR_FULL) {
		if (!(p = pa[++l]))
			break;
		n = n >> IDR_BITS;
		__set_bit((n & IDR_MASK), &p->bitmap);
	}
	return(id);
}

static int idr_get_new_above_int(struct idr *idp, void *ptr, int starting_id)
{
	struct idr_layer *p, *new;
	int layers, v, id;

	id = starting_id;
build_up:
	p = idp->top;
	layers = idp->layers;
	if (unlikely(!p)) {
		if (!(p = alloc_layer(idp)))
			return -1;
		layers = 1;
	}

	while ((layers < MAX_LEVEL) && (id >= (1 << (layers * IDR_BITS)))) {
		layers++;
		if (!p->count)
			continue;
		if (!(new = alloc_layer(idp))) {
			for (new = p; p && p != idp->top; new = p) {
				p = p->ary[0];
				new->ary[0] = NULL;
				new->bitmap = new->count = 0;
				free_layer(idp, new);
			}
			return -1;
		}
		new->ary[0] = p;
		new->count = 1;
		if (p->bitmap == IDR_FULL)
			__set_bit(0, &new->bitmap);
		p = new;
	}
	idp->top = p;
	idp->layers = layers;
	v = sub_alloc(idp, ptr, &id);
	if (v == -2)
		goto build_up;
	return(v);
}

int idr_get_new(struct idr *idp, void *ptr, int *id)
{
	int rv;
	rv = idr_get_new_above_int(idp, ptr, 0);
	if (rv < 0) {
		if (rv == -1)
			return -EAGAIN;
		else /* Will be -3 */
			return -ENOSPC;
	}
	*id = rv;
	return 0;
}

EXPORT_SYMBOL(idr_get_new);

static void idr_remove_warning(int id)
{
	printk("idr_remove called for id=%d which is not allocated.\n", id);
	dump_stack();
}

static void sub_remove(struct idr *idp, int shift, int id)
{
	struct idr_layer *p = idp->top;
	struct idr_layer **pa[MAX_LEVEL];
	struct idr_layer ***paa = &pa[0];
	int n;

	*paa = NULL;
	*++paa = &idp->top;

	while ((shift > 0) && p) {
		n = (id >> shift) & IDR_MASK;
		__clear_bit(n, &p->bitmap);
		*++paa = &p->ary[n];
		p = p->ary[n];
		shift -= IDR_BITS;
	}
	n = id & IDR_MASK;
	if (likely(p != NULL && test_bit(n, &p->bitmap))){
		__clear_bit(n, &p->bitmap);
		p->ary[n] = NULL;
		while(*paa && ! --((**paa)->count)){
			free_layer(idp, **paa);
			**paa-- = NULL;
		}
		if ( ! *paa )
			idp->layers = 0;
	} else {
		idr_remove_warning(id);
	}
}

void idr_remove(struct idr *idp, int id)
{
	struct idr_layer *p;

	/* Mask off upper bits we don't use for the search. */
	id &= MAX_ID_MASK;

	sub_remove(idp, (idp->layers - 1) * IDR_BITS, id);
	if ( idp->top && idp->top->count == 1 && 
	     (idp->layers > 1) &&
	     idp->top->ary[0]){  // We can drop a layer

		p = idp->top->ary[0];
		idp->top->bitmap = idp->top->count = 0;
		free_layer(idp, idp->top);
		idp->top = p;
		--idp->layers;
	}
	while (idp->id_free_cnt >= IDR_FREE_MAX) {
		
		p = alloc_layer(idp);
		kmem_cache_free(idr_layer_cache, p);
		return;
	}
}

EXPORT_SYMBOL(idr_remove);

static void idr_cache_ctor(void * idr_layer, 
			   kmem_cache_t *idr_layer_cache, unsigned long flags)
{
	memset(idr_layer, 0, sizeof(struct idr_layer));
}

static  int init_id_cache(void)
{
	if (!idr_layer_cache)
		idr_layer_cache = kmem_cache_create("idr_layer_cache", 
			sizeof(struct idr_layer), 0, 0, idr_cache_ctor, NULL);
	return 0;
}

/**
 * idr_init - initialize idr handle
 * @idp:	idr handle
 *
 * This function is use to set up the handle (@idp) that you will pass
 * to the rest of the functions.
 */
void idr_init(struct idr *idp) {
    init_id_cache();
    memset(idp, 0, sizeof(struct idr));
	spin_lock_init(&idp->lock);
}
EXPORT_SYMBOL(idr_init);