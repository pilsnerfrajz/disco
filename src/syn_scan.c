/* SPDX-License-Identifier: MIT */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include "../include/utils.h"
#include "../include/error.h"
#include "../include/headers.h"

#define SYN 0x02	 /* Sets the SYN flag in the TCP flag field */
#define SYN_ACK 0x12 /* Sets the SYN and ACK flag in the TCP flag field */
#define RST 0x04	 /* Sets the RST flag in the TCP flag field */
#define TIMEOUT_SECONDS 2

int port_scan(char *address)
{
	struct addrinfo *dst = get_dst_addr_struct(address, SOCK_RAW);
	if (dst == NULL)
	{
		return UNKNOWN_HOST;
	}

	struct protoent *protocol = getprotobyname("tcp");
	if (protocol == NULL)
	{
		free_dst_addr_struct(dst);
		return PROTO_NOT_FOUND;
	}

	int sfd = socket(dst->ai_family, SOCK_RAW, protocol->p_proto);
	if (sfd == -1)
	{
		free_dst_addr_struct(dst);
		if (errno == EPERM)
		{
			return PERMISSION_ERROR;
		}
		return SOCKET_ERROR;
	}

	int rv = set_socket_options(sfd, TIMEOUT_SECONDS);
	if (rv != 0)
	{
		free_dst_addr_struct(dst);
		return SOCKET_ERROR;
	}

	/* Use `connect` to make the OS set source IP and source port */
	rv = connect(sfd, dst->ai_addr, dst->ai_addrlen);
	if (rv != 0)
	{
		free_dst_addr_struct(dst);
		return SOCKET_ERROR;
	}

	/* Get the assigned source port */
	struct sockaddr_storage storage;
	socklen_t saddr_len = sizeof(storage);
	rv = getsockname(sfd, (struct sockaddr *)&storage, &saddr_len);
	if (rv != 0)
	{
		free_dst_addr_struct(dst);
		return SOCKET_ERROR;
	}

	struct sockaddr_in *s_addr_in = NULL;
	struct sockaddr_in6 *s_addr_in6 = NULL;
	u_int16_t src_port = 0;
	if (dst->ai_family == AF_INET)
	{
		s_addr_in = (struct sockaddr_in *)&storage;
		src_port = s_addr_in->sin_port;
	}
	else if (dst->ai_family == AF_INET6)
	{
		s_addr_in6 = (struct sockaddr_in6 *)&storage;
		src_port = s_addr_in6->sin6_port;
	}
	else
	{
		// error
	}

	// TODO Fix IP header as well for Linux support

	/* Declare header and init all fields to 0 */
	tcp_header_t tcp_hdr;
	memset(&tcp_hdr, 0, sizeof(tcp_header_t));
	tcp_hdr.sport = src_port;
	tcp_hdr.seq = htonl(arc4random()); /* rand is oboleted by this function */
	tcp_hdr.ack = htonl(0);
	tcp_hdr.offset_rsrvd.offset = 5;
	tcp_hdr.flags = SYN;
	tcp_hdr.window = htons(1024); /* Change to random later? */

	/* Fill in pseudo header depending on the address family of the target */
	tcp_pseudo_ipv4_t tcp_pseudo_ipv4;
	tcp_pseudo_ipv6_t tcp_pseudo_ipv6;
	if (dst->ai_family == AF_INET)
	{
		memset(&tcp_pseudo_ipv4, 0, sizeof(tcp_pseudo_ipv4_t));
		tcp_pseudo_ipv4.src_ip = s_addr_in->sin_addr.s_addr;
		tcp_pseudo_ipv4.dst_ip = ((struct sockaddr_in *)(dst->ai_addr))->sin_addr.s_addr;
		tcp_pseudo_ipv4.ptcl = protocol->p_proto;
		tcp_pseudo_ipv4.tcp_len = htons(sizeof(tcp_header_t));

		// TODO Change this
		tcp_hdr.dport = htons(80);

		/* Calculate checksum */
		size_t checksum_len = sizeof(tcp_header_t) + sizeof(tcp_pseudo_ipv4_t);
		u_int8_t *checksum_buf = malloc(checksum_len);
		if (checksum_buf == NULL)
		{
			free_dst_addr_struct(dst);
			return MEM_ALLOC_ERROR;
		}
		/* Copy pseudo header and TCP header into a buffer */
		memcpy(checksum_buf, &tcp_pseudo_ipv4, sizeof(tcp_pseudo_ipv4_t));
		memcpy(checksum_buf + sizeof(tcp_pseudo_ipv4_t), &tcp_hdr, sizeof(tcp_header_t));
		tcp_hdr.checksum = calc_checksum(checksum_buf, checksum_len);

		// send to first port
		u_int8_t *send_buf = (u_int8_t *)&tcp_hdr;
		ssize_t bytes_left = sizeof(tcp_header_t);
		ssize_t total_sent = 0;
		ssize_t sent;
		while (total_sent < bytes_left)
		{
			sent = send(sfd, send_buf + total_sent, bytes_left - total_sent, 0);
			if (sent == -1)
			{
				free_dst_addr_struct(dst);
				free(checksum_buf);
				return SOCKET_ERROR;
			}
			total_sent += sent;
		}

		// wait for answer and check RST or SYN-ACK

		// print or save results

		// change port number and maybe src port

		// recalculate checksum

		// send and repeat

		// free
		free(checksum_buf);
	}
	else if (dst->ai_family == AF_INET6)
	{
		memset(&tcp_pseudo_ipv6, 0, sizeof(tcp_pseudo_ipv6_t));
		tcp_pseudo_ipv6.src_ip = s_addr_in6->sin6_addr;
		tcp_pseudo_ipv6.dst_ip = ((struct sockaddr_in6 *)(dst->ai_addr))->sin6_addr;
		tcp_pseudo_ipv6.next = protocol->p_proto;
		tcp_pseudo_ipv6.length = htonl(sizeof(tcp_header_t));
	}
	else
	{
		// error
	}

	/* Scan well-known ports to start with */
	// for (int port = 1; port <= 1024; port++)
	//{
	//	tcp_hdr.dport = htons(port);

	/* Reset checksum */
	// tcp_hdr.checksum = htons(0);
	//}

	free_dst_addr_struct(dst);

	return SUCCESS;
}
