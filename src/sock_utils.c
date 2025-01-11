#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/sock_utils.h"

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
		return NULL;
	}

	return temp;
}

void print_ip(struct sockaddr_in *s)
{
	char ip_str[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &s->sin_addr, ip_str, INET_ADDRSTRLEN) != NULL)
	{
		printf("%s\n", ip_str);
	}
}
