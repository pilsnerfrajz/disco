#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

/**
 * @brief Gets a pointer to an addrinfo structure for the destination
 * IP address. Allows socket setup to be IP-address family agnostic.
 * The returned struct should be freed with `freeaddrinfo()`.
 *
 * @param dst IP string.
 * @return `struct addrinfo*` on success. `NULL` if an error occurs.
 */
struct addrinfo *get_dst_addr_struct(char *dst)
{
	struct addrinfo *dst_info;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
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
