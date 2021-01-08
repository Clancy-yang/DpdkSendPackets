#include "rte_ring.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

/* true if x is a power of 2 */
#define POWEROF2(x) ((((x)-1) & (x)) == 0)

/* return the size of memory occupied by a ring */
ssize_t
hx_rte_ring_get_memsize(unsigned count)
{
    ssize_t sz;

    /* count must be a power of 2 */
    if ((!POWEROF2(count)) || (count > hx_rte_RING_SZ_MASK )) {
        return -EINVAL;
    }
    sz = sizeof(struct hx_rte_ring) + count * sizeof(void *);
    return sz;
}

int
hx_rte_ring_init(struct hx_rte_ring *r, const char *name, unsigned count,
              unsigned flags)
{
    int ret;

    /* init the ring structure */
    memset(r, 0, sizeof(*r));
    ret = snprintf(r->name, sizeof(r->name), "%s", name);
    if (ret < 0 || ret >= (int)sizeof(r->name))
        return -ENAMETOOLONG;
    r->flags = flags;
    r->prod.single = (flags & RING_F_SP_ENQ) ? __IS_SP : __IS_MP;
    r->cons.single = (flags & RING_F_SC_DEQ) ? __IS_SC : __IS_MC;

    if (flags & RING_F_EXACT_SZ) {
        r->size = hx_rte_align32pow2(count + 1);
        r->mask = r->size - 1;
        r->capacity = count;
    } else {
        if ((!POWEROF2(count)) || (count > hx_rte_RING_SZ_MASK)) {
            return -EINVAL;
        }
        r->size = count;
        r->mask = count - 1;
        r->capacity = r->mask;
    }
    r->prod.head = r->cons.head = 0;
    r->prod.tail = r->cons.tail = 0;

    return 0;
}
#define valloc malloc
#define vfree free
/* create the ring */
struct hx_rte_ring *
hx_rte_ring_create(const char *name, unsigned count,
                unsigned flags)
{
    char mz_name[hx_rte_NAMESIZE];
    struct hx_rte_ring *r;
    struct rte_tailq_entry *te;
    const struct rte_memzone *mz;
    ssize_t ring_size;
    int mz_flags = 0;
    const unsigned int requested_count = count;
    int ret;

    /* for an exact size ring, round up from count to a power of two */
    if (flags & RING_F_EXACT_SZ)
        count = hx_rte_align32pow2(count + 1);

    ring_size = hx_rte_ring_get_memsize(count);
    if (ring_size < 0) {
        return NULL;
    }

    ret = snprintf(mz_name, sizeof(mz_name), "%s%s",
                   hx_rte_RING_MZ_PREFIX, name);
    if (ret < 0 || ret >= (int)sizeof(mz_name)) {
        return NULL;
    }

    r = (struct  hx_rte_ring *)valloc(ring_size);

    hx_rte_ring_init(r, name, requested_count, flags);

    return r;
}

/* free the ring */
void
hx_rte_ring_free(struct hx_rte_ring *r)
{
    if (r == NULL)
        return;
    vfree(r);
}

/* dump the status of the ring on the console */
void
hx_rte_ring_dump(FILE *f, const struct hx_rte_ring *r)
{
    fprintf(f, "ring <%s>@%p\n", r->name, r);
    fprintf(f, "  flags=%x\n", r->flags);
    fprintf(f, "  size=%"PRIu32"\n", r->size);
    fprintf(f, "  capacity=%"PRIu32"\n", r->capacity);
    fprintf(f, "  ct=%"PRIu32"\n", r->cons.tail);
    fprintf(f, "  ch=%"PRIu32"\n", r->cons.head);
    fprintf(f, "  pt=%"PRIu32"\n", r->prod.tail);
    fprintf(f, "  ph=%"PRIu32"\n", r->prod.head);
    fprintf(f, "  used=%u\n", hx_rte_ring_count(r));
    fprintf(f, "  avail=%u\n", hx_rte_ring_free_count(r));
}
