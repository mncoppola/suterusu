#include "common.h"

int success_int ( void )
{
    return 0;
}

void success_void ( void )
{
}

int module_handler ( struct notifier_block *nblock, unsigned long code, void *_param )
{
    unsigned long flags;
    struct module *param = _param;
    DEFINE_SPINLOCK(module_event_spinlock);

    spin_lock_irqsave(&module_event_spinlock, flags);

    switch ( param->state )
    {
        case MODULE_STATE_COMING:
            DEBUG("Detected insertion of module '%s', neutralizing init and exit routines\n", param->name);
            param->init = success_int;
            param->exit = success_void;
            break;

        default:
            break;
    }

    spin_unlock_irqrestore(&module_event_spinlock, flags);

    return NOTIFY_DONE;
}

static struct notifier_block nb = {
    .notifier_call = module_handler,
    .priority = INT_MAX,
};

void disable_module_loading ( void )
{
    register_module_notifier(&nb);
}

void enable_module_loading ( void )
{
    unregister_module_notifier(&nb);
}
