/* SPDX-License-Identifier: MIT */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>

#include "../include/utils.h"
#include "../include/error.h"
#include "../include/syn_scan.h"

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

	// set socket options to timeout if no response is seen

	// TODO Fix IP header as well for Linux support

	/* Declare structs and init all fields to 0 */
	tcp_header_t tcp_hdr;
	tcp_flags_t flags;
	memset(&tcp_hdr, 0, sizeof(tcp_header_t));
	memset(&flags, 0, sizeof(tcp_flags_t));

	flags.syn = 1;
	tcp_hdr.flags = *(u_int8_t *)&flags;
	tcp_hdr.offset_rsrvd.offset = 5;
	// set rest of fields

	// send to first port

	// wait for answer and check RST or SYN-ACK

	// print or save results

	// change port number and maybe src port

	// send and repeat

	free_dst_addr_struct(dst);

	return SUCCESS;
}
