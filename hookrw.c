#include "common.h"
#include <asm/uaccess.h>

asmlinkage long (*sys_write)(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long (*sys_read)(unsigned int fd, char __user *buf, size_t count);

void hook_read ( unsigned int *fd, char __user *buf, size_t *count )
{
    /* Monitor/manipulate sys_read() arguments here */
}

void hook_write ( unsigned int *fd, const char __user *buf, size_t *count )
{
    /* Monitor/manipulate sys_write() arguments here */
}

asmlinkage long n_sys_read ( unsigned int fd, char __user *buf, size_t count )
{
    long ret;

    #if __DEBUG_RW__
    void *debug;

    debug = kmalloc(count, GFP_KERNEL);
    if ( ! debug )
    {
        DEBUG_RW("ERROR: Failed to allocate %lu bytes for sys_read debugging\n", count);
    }
    else
    {
        if ( copy_from_user(debug, buf, count) )
        {
            DEBUG_RW("ERROR: Failed to copy %lu bytes from user for sys_read debugging\n", count);
            kfree(debug);
        }
        else
        {
            if ( memstr(debug, "filter keyword", count) )
            {
                unsigned long i;
                DEBUG_RW("DEBUG sys_read: fd=%d, count=%zu, buf=\n", fd, count);
                for ( i = 0; i < count; i++ )
                    DEBUG_RW("%x", *((unsigned char *)debug + i));
                DEBUG_RW("\n");
            }
            kfree(debug);
        }
    }
    #endif

    hook_read(&fd, buf, &count);

    hijack_pause(sys_read);
    ret = sys_read(fd, buf, count);
    hijack_resume(sys_read);

    return ret;
}

asmlinkage long n_sys_write ( unsigned int fd, const char __user *buf, size_t count )
{
    long ret;

    #if __DEBUG_RW__
    void *debug;

    debug = kmalloc(count, GFP_KERNEL);
    if ( ! debug )
    {
        DEBUG_RW("ERROR: Failed to allocate %lu bytes for sys_write debugging\n", count);
    }
    else
    {
        if ( copy_from_user(debug, buf, count) )
        {
            DEBUG_RW("ERROR: Failed to copy %lu bytes from user for sys_write debugging\n", count);
            kfree(debug);
        }
        else
        {
            if ( memstr(debug, "filter keyword", count) )
            {
                unsigned long i;
                DEBUG_RW("DEBUG sys_write: fd=%d, count=%zu, buf=\n", fd, count);
                for ( i = 0; i < count; i++ )
                    DEBUG_RW("%x", *((unsigned char *)debug + i));
                DEBUG_RW("\n");
            }
            kfree(debug);
        }
    }
    #endif

    hook_write(&fd, buf, &count);

    hijack_pause(sys_write);
    ret = sys_write(fd, buf, count);
    hijack_resume(sys_write);

    return ret;
}

void hookrw_init ( void )
{
    DEBUG("Hooking sys_read and sys_write\n");

    sys_read = (void *)sys_call_table[__NR_read];
    hijack_start(sys_read, &n_sys_read);

    sys_write = (void *)sys_call_table[__NR_write];
    hijack_start(sys_write, &n_sys_write);
}

void hookrw_exit ( void )
{
    DEBUG("Unhooking sys_read and sys_write\n");

    hijack_stop(sys_read);
    hijack_stop(sys_write);
}
