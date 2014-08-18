#include "common.h"
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>
#if defined(_CONFIG_ARM_) && defined(CONFIG_STRICT_MEMORY_RWX)
#include <asm/mmu_writeable.h>
#endif

#if defined(_CONFIG_X86_)
    #define HIJACK_SIZE 6
#elif defined(_CONFIG_X86_64_)
    #define HIJACK_SIZE 12
#else // ARM
    #define HIJACK_SIZE 12
#endif

struct sym_hook {
    void *addr;
    unsigned char o_code[HIJACK_SIZE];
    unsigned char n_code[HIJACK_SIZE];
    struct list_head list;
};

struct ksym {
    char *name;
    unsigned long addr;
};

LIST_HEAD(hooked_syms);

#if defined(_CONFIG_X86_) || defined(_CONFIG_X86_64_)
// Thanks Dan
inline unsigned long disable_wp ( void )
{
    unsigned long cr0;

    preempt_disable();
    barrier();

    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    return cr0;
}

inline void restore_wp ( unsigned long cr0 )
{
    write_cr0(cr0);

    barrier();
    preempt_enable();
}
#else // ARM
void cacheflush ( void *begin, unsigned long size )
{
    flush_icache_range((unsigned long)begin, (unsigned long)begin + size);
}

# if defined(CONFIG_STRICT_MEMORY_RWX)
inline void arm_write_hook ( void *target, char *code )
{
    unsigned long *target_arm = (unsigned long *)target;
    unsigned long *code_arm = (unsigned long *)code;

    // We should have something more generalized here, but we'll
    // get away with it since the ARM hook is always 12 bytes
    mem_text_write_kernel_word(target_arm, *code_arm);
    mem_text_write_kernel_word(target_arm + 1, *(code_arm + 1));
    mem_text_write_kernel_word(target_arm + 2, *(code_arm + 2));
}
# else
inline void arm_write_hook ( void *target, char *code )
{
    memcpy(target, code, HIJACK_SIZE);
    cacheflush(target, HIJACK_SIZE);
}
# endif
#endif

void hijack_start ( void *target, void *new )
{
    struct sym_hook *sa;
    unsigned char o_code[HIJACK_SIZE], n_code[HIJACK_SIZE];

    #if defined(_CONFIG_X86_)
    unsigned long o_cr0;

    // push $addr; ret
    memcpy(n_code, "\x68\x00\x00\x00\x00\xc3", HIJACK_SIZE);
    *(unsigned long *)&n_code[1] = (unsigned long)new;
    #elif defined(_CONFIG_X86_64_)
    unsigned long o_cr0;

    // mov rax, $addr; jmp rax
    memcpy(n_code, "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0", HIJACK_SIZE);
    *(unsigned long *)&n_code[2] = (unsigned long)new;
    #else // ARM
    if ( (unsigned long)target % 4 == 0 )
    {
        // ldr pc, [pc, #0]; .long addr; .long addr
        memcpy(n_code, "\x00\xf0\x9f\xe5\x00\x00\x00\x00\x00\x00\x00\x00", HIJACK_SIZE);
        *(unsigned long *)&n_code[4] = (unsigned long)new;
        *(unsigned long *)&n_code[8] = (unsigned long)new;
    }
    else // Thumb
    {
        // add r0, pc, #4; ldr r0, [r0, #0]; mov pc, r0; mov pc, r0; .long addr
        memcpy(n_code, "\x01\xa0\x00\x68\x87\x46\x87\x46\x00\x00\x00\x00", HIJACK_SIZE);
        *(unsigned long *)&n_code[8] = (unsigned long)new;
        target--;
    }
    #endif

    DEBUG_HOOK("Hooking function 0x%p with 0x%p\n", target, new);

    memcpy(o_code, target, HIJACK_SIZE);

    #if defined(_CONFIG_X86_) || defined(_CONFIG_X86_64_)
    o_cr0 = disable_wp();
    memcpy(target, n_code, HIJACK_SIZE);
    restore_wp(o_cr0);
    #else // ARM
    arm_write_hook(target, n_code);
    #endif

    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if ( ! sa )
        return;

    sa->addr = target;
    memcpy(sa->o_code, o_code, HIJACK_SIZE);
    memcpy(sa->n_code, n_code, HIJACK_SIZE);

    list_add(&sa->list, &hooked_syms);
}

void hijack_pause ( void *target )
{
    struct sym_hook *sa;

    DEBUG_HOOK("Pausing function hook 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            #if defined(_CONFIG_X86_) || defined(_CONFIG_X86_64_)
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->o_code, HIJACK_SIZE);
            restore_wp(o_cr0);
            #else // ARM
            arm_write_hook(target, sa->o_code);
            #endif
        }
}

void hijack_resume ( void *target )
{
    struct sym_hook *sa;

    DEBUG_HOOK("Resuming function hook 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            #if defined(_CONFIG_X86_) || defined(_CONFIG_X86_64_)
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->n_code, HIJACK_SIZE);
            restore_wp(o_cr0);
            #else // ARM
            arm_write_hook(target, sa->n_code);
            #endif
        }
}

void hijack_stop ( void *target )
{
    struct sym_hook *sa;

    DEBUG_HOOK("Unhooking function 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            #if defined(_CONFIG_X86_) || defined(_CONFIG_X86_64_)
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->o_code, HIJACK_SIZE);
            restore_wp(o_cr0);
            #else // ARM
            arm_write_hook(target, sa->o_code);
            #endif

            list_del(&sa->list);
            kfree(sa);
            break;
        }
}

char *strnstr ( const char *haystack, const char *needle, size_t n )
{
    char *s = strstr(haystack, needle);

    if ( s == NULL )
        return NULL;

    if ( s - haystack + strlen(needle) <= n )
        return s;
    else
        return NULL;
}

void *memmem ( const void *haystack, size_t haystack_size, const void *needle, size_t needle_size )
{
    char *p;

    for ( p = (char *)haystack; p <= ((char *)haystack - needle_size + haystack_size); p++ )
        if ( memcmp(p, needle, needle_size) == 0 )
            return (void *)p;

    return NULL;
}

void *memstr ( const void *haystack, const char *needle, size_t size )
{
    char *p;
    size_t needle_size = strlen(needle);

    for ( p = (char *)haystack; p <= ((char *)haystack - needle_size + size); p++ )
        if ( memcmp(p, needle, needle_size) == 0 )
            return (void *)p;

    return NULL;
}

int find_ksym ( void *data, const char *name, struct module *module, unsigned long address )
{
    struct ksym *ksym = (struct ksym *)data;
    char *target = ksym->name;

    if ( strncmp(target, name, KSYM_NAME_LEN) == 0 )
    {
        ksym->addr = address;
        return 1;
    }

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
unsigned long get_symbol ( char *name )
{
    unsigned long symbol = 0;
    struct ksym ksym;

    /*
     * kallsyms_lookup_name() is re-exported in 2.6.33, but there's no real
     * benefit to using it instead of kallsyms_on_each_symbol().  We also get
     * to remove one more LINUX_VERSION_CODE check.
     */

    ksym.name = name;
    ksym.addr = 0;
    kallsyms_on_each_symbol(&find_ksym, &ksym);
    symbol = ksym.addr;

    return symbol;
}
#endif
