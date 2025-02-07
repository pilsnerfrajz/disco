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
#include "../include/syn_scan.h"

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

	/* Use connect to make the OS set source IP and source port */
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
	u_int16_t src_port;
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

	// TODO Fix IP header as well for Linux support

	/* Declare header and init all fields to 0 */
	tcp_header_t tcp_hdr;
	memset(&tcp_hdr, 0, sizeof(tcp_header_t));

	tcp_hdr.sport = src_port;
	// tcp_hdr.dport
	tcp_hdr.seq = htonl(arc4random()); /* rand is oboleted by this function */
	tcp_hdr.ack = htonl(0);
	tcp_hdr.offset_rsrvd.offset = 5;
	tcp_hdr.flags = SYN;
	tcp_hdr.window = htons(1024); /* Change to random later? */
	// tcp_hdr.checksum

	// send to first port

	// wait for answer and check RST or SYN-ACK

	// print or save results

	// change port number and maybe src port

	// send and repeat

	free_dst_addr_struct(dst);

	return SUCCESS;
}
