#ifndef HX_RTE_RING_HX_RTE_ATOMIC_X86_H
#define HX_RTE_RING_HX_RTE_ATOMIC_X86_H

#define	rte_compiler_barrier() do {		\
	asm volatile ("" : : : "memory");	\
} while(0)

#define MPLOCKED        "lock ; "
/*------------------------- 32 bit atomic operations -------------------------*/
static inline int
hx_rte_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
    uint8_t res;

    asm volatile(
    MPLOCKED
    "cmpxchgl %[src], %[dst];"
    "sete %[res];"
    : [res] "=a" (res),     /* output */
    [dst] "=m" (*dst)
    : [src] "r" (src),      /* input */
            "a" (exp),
            "m" (*dst)
    : "memory");            /* no-clobber list */
    return res;
}

#define hx_rte_smp_wmb() rte_compiler_barrier()

#define hx_rte_smp_rmb() rte_compiler_barrier()

#endif //HX_RTE_RING_HX_RTE_ATOMIC_X86_H
