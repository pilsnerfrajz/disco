#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <errno.h>

#define TIMEOUT_SECONDS 2

int validate_ip(char *ip)
{
	struct in_addr ipv4_dst;
	struct in6_addr ipv6_dst;
	if (inet_pton(AF_INET, ip, &(ipv4_dst)) == 1 ||
		inet_pton(AF_INET6, ip, &(ipv6_dst)) == 1)
	{
		return 0;
	}
	return -1;
}

struct addrinfo *get_dst_addr_struct(char *dst)
{
	struct addrinfo *dst_info;
	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags = AI_PASSIVE;

	int ret = getaddrinfo(dst, NULL, &hints, &dst_info);
	if (ret != 0)
	{
		freeaddrinfo(dst_info);
		return NULL;
	}

	struct addrinfo *temp = dst_info;
	while (temp != NULL)
	{
		if (temp->ai_family == AF_INET || temp->ai_family == AF_INET6)
		{
			break;
		}
		temp = temp->ai_next;
	}

	if (temp == NULL)
	{
		freeaddrinfo(dst_info);
		return NULL;
	}

	return dst_info;
}

struct protoent *get_proto(struct addrinfo *dst_info)
{
	struct protoent *protocol;
	if (dst_info->ai_family == AF_INET)
	{
		protocol = getprotobyname("icmp");
	}
	else
	{
		protocol = getprotobyname("icmp6");
	}

	if (protocol == NULL)
	{
		return NULL;
	}

	return protocol;
}

int set_socket_options(int sfd)
{
	struct timeval timeout = {
		.tv_sec = TIMEOUT_SECONDS,
		.tv_usec = 0,
	};

	int rv = setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (rv == -1)
	{
		perror("Setsockopt");
		return -1;
	}

	return 0;
}

void exit_error(struct addrinfo *dst)
{
	freeaddrinfo(dst);
	exit(EXIT_FAILURE);
}

int ping(char *dst)
{
	int rv = validate_ip(dst);
	if (rv == -1)
	{
		fprintf(stderr, "Invalid IP address.\n");
		exit(EXIT_FAILURE);
	}

	struct addrinfo *dst_info = get_dst_addr_struct(dst);
	if (dst_info == NULL)
	{
		fprintf(stderr, "Failed getting target address info.\n");
		exit_error(dst_info);
	}

	struct protoent *protocol = get_proto(dst_info);
	if (protocol == NULL)
	{
		fprintf(stderr, "Could not find a protocol with the given name.\n");
		exit(EXIT_FAILURE);
	}

	int sfd = socket(dst_info->ai_family, SOCK_RAW, protocol->p_proto);
	if (sfd == -1)
	{
		perror("Socket");
		exit_error(dst_info);
	}

	rv = set_socket_options(sfd);
	if (rv == -1)
	{
		exit_error(dst_info);
	}

	rv = connect(sfd, dst_info->ai_addr, dst_info->ai_addrlen);
	if (rv < 0)
	{
		perror("Connect");
		exit_error(dst_info);
	}

	printf("OK\n");
	return 0;
}