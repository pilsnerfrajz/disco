/* SPDX-License-Identifier: MIT */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>

#include "../include/utils.h"
#include "../include/error.h"
#include "../include/headers.h"

#define SYN 0x02	 /* Sets the SYN flag in the TCP flag field */
#define SYN_ACK 0x12 /* Sets the SYN and ACK flag in the TCP flag field */
#define RST 0x04	 /* Sets the RST flag in the TCP flag field */
#define TIMEOUT_SECONDS 2
#define RETRIES 3

/*
 * Max IPv4 header size = 60 bytes
 * Max TCP header size = 60 bytes
 */
#define TCP_IPv4_BUF 120
/*
 * Max IPv6 header size = 40 bytes
 * Max TCP header size = 60 bytes
 */
#define TCP_IPv6_BUF 100

struct src_info
{
	char *ip;
	int port;
};

/**
 * @brief Gets the source IP and possible port used to connect to the target in
 * `dst`. This function is a workaround as the `connect` call combined with
 * `getsockname` does not seem to work with the `addrinfo struct`. At least
 * on macOS.
 *
 * @param dst target info.
 * @param src_info struct to store source information in.
 * @return int returns 0 on success. SOCKET_ERROR or -1 is returned if an error
 * occurs.
 */
int get_src_info(struct addrinfo *dst, struct src_info *src_info)
{
	int sock = socket(dst->ai_family, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror("Socket creation failed");
		return SOCKET_ERROR;
	}

	struct sockaddr_in remote_addr;
	struct sockaddr_in6 remote_addr6;
	struct sockaddr_in local_addr;
	struct sockaddr_in6 local_addr6;

	if (dst->ai_family == AF_INET)
	{
		memset(&remote_addr, 0, sizeof(remote_addr));
		remote_addr.sin_family = AF_INET;
		remote_addr.sin_port = htons(53);
		remote_addr.sin_addr = ((struct sockaddr_in *)dst->ai_addr)->sin_addr;

		if (connect(sock, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0)
		{
			perror("Connect failed");
			close(sock);
			return SOCKET_ERROR;
		}

		socklen_t addr_len = sizeof(local_addr);
		if (getsockname(sock, (struct sockaddr *)&local_addr, &addr_len) < 0)
		{
			perror("getsockname failed");
			close(sock);
			return SOCKET_ERROR;
		}

		src_info->ip = malloc(INET_ADDRSTRLEN);
		if (src_info->ip == NULL)
		{
			close(sock);
			return -1;
		}
		/* Copy ip into struct */
		if (inet_ntop(AF_INET, &local_addr.sin_addr, src_info->ip, INET_ADDRSTRLEN) == NULL)
		{
			return -1;
		}

		src_info->port = ntohs(local_addr.sin_port);
	}
	else if (dst->ai_family == AF_INET6)
	{
		memset(&remote_addr6, 0, sizeof(remote_addr6));
		remote_addr6.sin6_family = AF_INET6;
		remote_addr6.sin6_port = htons(53);
		remote_addr6.sin6_addr = ((struct sockaddr_in6 *)dst->ai_addr)->sin6_addr;

		if (connect(sock, (struct sockaddr *)&remote_addr6, sizeof(remote_addr6)) < 0)
		{
			perror("Connect failed");
			close(sock);
			return SOCKET_ERROR;
		}

		socklen_t addr_len = sizeof(local_addr6);
		if (getsockname(sock, (struct sockaddr *)&local_addr6, &addr_len) < 0)
		{
			perror("getsockname failed");
			close(sock);
			return SOCKET_ERROR;
		}

		src_info->ip = malloc(INET6_ADDRSTRLEN);
		if (src_info->ip == NULL)
		{
			close(sock);
			return -1;
		}

		if (inet_ntop(AF_INET6, &local_addr6.sin6_addr, src_info->ip, INET6_ADDRSTRLEN) == NULL)
		{
			return -1;
		}

		src_info->port = ntohs(local_addr6.sin6_port);
	}
	else
	{
		// error
		return -1;
	}

	close(sock);
	return 0;
}

int port_scan(char *address)
{
	struct addrinfo *dst = get_dst_addr_struct(address, SOCK_RAW);
	if (dst == NULL)
	{
		return UNKNOWN_HOST;
	}

	struct src_info src_info = {0};
	get_src_info(dst, &src_info);

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
		printf("Socket\n");
		return SOCKET_ERROR;
	}

	int rv = set_socket_options(sfd, TIMEOUT_SECONDS);
	if (rv != 0)
	{
		free_dst_addr_struct(dst);
		printf("Socket op\n");
		close(sfd);
		return SOCKET_ERROR;
	}

	int one = 1;
	rv = setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
	if (rv < 0)
	{
		perror("setsockopt IP_HDRINCL failed");
		close(sfd);
		return SOCKET_ERROR;
	}

	rv = bind(sfd, )

		/* Use `connect` to make the OS set source IP and source port */
		/*rv = connect(sfd, dst->ai_addr, dst->ai_addrlen);
		if (rv != 0)
		{
			free_dst_addr_struct(dst);
			perror("connect");
			close(sfd);
			return SOCKET_ERROR;
		}*/

		/* Get the assigned source port */
		/*struct sockaddr_storage storage;
		socklen_t saddr_len = sizeof(storage);
		rv = getsockname(sfd, (struct sockaddr *)&storage, &saddr_len);
		if (rv == -1)
		{
			free_dst_addr_struct(dst);
			printf("Getsock\n");
			close(sfd);
			return SOCKET_ERROR;
		}*/

		/*struct sockaddr_in *s_addr_in = NULL;
		struct sockaddr_in6 *s_addr_in6 = NULL;
		u_int16_t src_port = 0;
		if (dst->ai_family == AF_INET)
		{
			s_addr_in = (struct sockaddr_in *)&storage;
			src_port = s_addr_in->sin_port;
			char ip_str[INET_ADDRSTRLEN];
			if (inet_ntop(AF_INET, &s_addr_in->sin_addr, ip_str, INET_ADDRSTRLEN) != NULL)
			{
				printf("Source IP: %s\n", ip_str);
			}
			else
			{
				perror("inet_ntop");
				close(sfd);
				return SOCKET_ERROR;
			}

			printf("Source PORT: %d\n", ntohs(src_port));
		}
		else if (dst->ai_family == AF_INET6)
		{
			s_addr_in6 = (struct sockaddr_in6 *)&storage;
			char ip_str[INET6_ADDRSTRLEN];
			if (inet_ntop(AF_INET6, &s_addr_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN) != NULL)
			{
				printf("IP: %s\n", ip_str);
			}
			printf("%d\n", ntohs(s_addr_in6->sin6_port));
			return 0;
			// src_port = storage.sin6_port;
			// printf("PORT: %d\n", ntohs(src_port));
		}
		else
		{
			// error
		}*/

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
			close(sfd);
			return MEM_ALLOC_ERROR;
		}

		tcp_hdr.checksum = 0;
		tcp_hdr.checksum = htons(calc_checksum(checksum_buf, checksum_len));
		printf("Checksum: %d\n", ntohs(tcp_hdr.checksum));
		char nprint[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(s_addr_in->sin_addr), nprint, INET_ADDRSTRLEN);
		printf("SRC: %s\n", nprint);

		/* Copy pseudo header and TCP header into a buffer */
		memcpy(checksum_buf, &tcp_pseudo_ipv4, sizeof(tcp_pseudo_ipv4_t));
		memcpy(checksum_buf + sizeof(tcp_pseudo_ipv4_t), &tcp_hdr, sizeof(tcp_header_t));

		// TODO ADD IP HEADER
		struct ip ip_header;
		memset(&ip_header, 0, sizeof(struct ip));
		ip_header.ip_dst = ((struct sockaddr_in *)dst)->sin_addr;
		ip_header.ip_src = s_addr_in->sin_addr;
		ip_header.ip_v = 4;	 /* Version 4 */
		ip_header.ip_hl = 5; /* Header length, no options */
		ip_header.ip_len = htons(sizeof(struct ip) + sizeof(tcp_header_t));
		ip_header.ip_id = htons(arc4random() & 0xffff); /* 16 bits */
		ip_header.ip_ttl = 64;							/* Mac and Linux default */
		ip_header.ip_p = (u_char)protocol->p_proto;		/* TCP */
		ip_header.ip_sum = htons(calc_checksum(&ip_header, sizeof(struct ip)));

		struct ip_packet
		{
			struct ip ip_hdr;
			tcp_header_t tcp_hdr;
		};

		struct ip_packet ip_pkt = {
			.ip_hdr = ip_header,
			.tcp_hdr = tcp_hdr,
		};

		/*int optval = 1;
		if (setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0)
		{
			perror("setsockopt");
			return SOCKET_ERROR;
		}*/

		printf("Raw Packet (IP Header + TCP Header):\n");
		for (size_t i = 0; i < sizeof(struct ip_packet); i++)
		{
			printf("%02x ", ((unsigned char *)&ip_pkt)[i]);
			if ((i + 1) % 16 == 0)
			{
				printf("\n");
			}
		}
		printf("\n");

		// send to first port
		u_int8_t *send_buf = (u_int8_t *)&ip_pkt;
		ssize_t bytes_left = sizeof(struct ip_packet);
		ssize_t total_sent = 0;
		ssize_t sent;
		while (total_sent < bytes_left)
		{
			sent = send(sfd, send_buf + total_sent, bytes_left - total_sent, 0);
			if (sent == -1)
			{
				free_dst_addr_struct(dst);
				free(checksum_buf);
				perror("send");
				close(sfd);
				return SOCKET_ERROR;
			}
			total_sent += sent;
		}

		// wait for answer and check RST or SYN-ACK
		for (int retry = 0; retry < RETRIES; retry++)
		{
			char recvbuf[TCP_IPv4_BUF];
			rv = recv(sfd, recvbuf, TCP_IPv4_BUF, 0);
			printf("Recv bytes: %d\n", rv);
			if (rv < 0)
			{
				free_dst_addr_struct(dst);
				free(checksum_buf);
				perror("recv");
				close(sfd);
				return SOCKET_ERROR;
			}

			struct ip *ip_len = (struct ip *)recvbuf;
			/* Jump past IP header and get the TCP header */
			tcp_header_t *recv_tcp_hdr = (tcp_header_t *)(recvbuf + ip_len->ip_hl * 4);
			if (recv_tcp_hdr->dport != tcp_hdr.sport)
			{
				continue;
			}
			if (recv_tcp_hdr->sport != tcp_hdr.dport)
			{
				continue;
			}
			if (tcp_hdr.seq + htonl(1) != recv_tcp_hdr->ack)
			{
				continue;
			}
			if (recv_tcp_hdr->flags == SYN_ACK)
			{
				printf("PORT IS OPEN\n");
			}
			if (recv_tcp_hdr->flags == RST)
			{
				printf("PORT IS CLOSED\n");
			}
		}

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

	free(src_info.ip);
	free_dst_addr_struct(dst);
	close(sfd);

	return SUCCESS;
}
