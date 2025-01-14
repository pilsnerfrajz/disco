#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "../include/utils.h"

void free_dst_addr_struct(struct addrinfo *dst)
{
	if (dst == NULL)
	{
		return;
	}
	if (dst->ai_addr != NULL)
	{
		free(dst->ai_addr);
	}

	free(dst);
}

struct addrinfo *get_dst_addr_struct(char *dst, int sock_type)
{
	struct addrinfo *dst_info;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = sock_type;
	hints.ai_flags = AI_PASSIVE;

	int ret = getaddrinfo(dst, NULL, &hints, &dst_info);
	if (ret != 0)
	{
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

	struct addrinfo *res = malloc(sizeof(struct addrinfo));
	if (res == NULL)
	{
		freeaddrinfo(dst_info);
		return NULL;
	}

	res->ai_addr = malloc(sizeof(struct addrinfo));
	if (res->ai_addr == NULL)
	{
		freeaddrinfo(dst_info);
		return NULL;
	}
	memcpy(res->ai_addr, temp->ai_addr, sizeof(struct addrinfo));
	res->ai_family = temp->ai_family;
	res->ai_addrlen = temp->ai_addrlen;

	freeaddrinfo(dst_info);
	return res;
}

void print_ip(struct sockaddr_in *s)
{
	char ip_str[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &s->sin_addr, ip_str, INET_ADDRSTRLEN) != NULL)
	{
		printf("%s\n", ip_str);
	}
}
