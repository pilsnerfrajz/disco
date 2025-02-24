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
	u_int16_t port;
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
			close(sock);
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
			close(sock);
			return -1;
		}

		src_info->port = ntohs(local_addr6.sin6_port);
	}
	else
	{
		// error
		close(sock);
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
		close(sfd);
		return SOCKET_ERROR;
	}

	// TODO Keep? Not needed on Linux
	/*int one = 1;
	rv = setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
	if (rv < 0)
	{
		perror("setsockopt");
		free_dst_addr_struct(dst);
		close(sfd);
		return SOCKET_ERROR;
	}*/

	/* Fix struct to use in bind */
	struct sockaddr *bind_ptr;
	socklen_t bind_ptr_len = 0;
	struct sockaddr_in bind_ipv4;
	struct sockaddr_in6 bind_ipv6;
	if (dst->ai_family == AF_INET)
	{
		memset(&bind_ipv4, 0, sizeof(struct sockaddr_in));
		bind_ipv4.sin_family = AF_INET;
		bind_ipv4.sin_port = htons(src_info.port);
		if (inet_pton(AF_INET, src_info.ip, &bind_ipv4.sin_addr) <= 0)
		{
			free_dst_addr_struct(dst);
			close(sfd);
			return SOCKET_ERROR;
		}

		bind_ptr = (struct sockaddr *)&bind_ipv4;
		bind_ptr_len = sizeof(struct sockaddr_in);
	}
	else if (dst->ai_family == AF_INET6)
	{
		memset(&bind_ipv6, 0, sizeof(struct sockaddr_in6));
		bind_ipv6.sin6_family = AF_INET6;
		bind_ipv6.sin6_port = htons(src_info.port);
		if (inet_pton(AF_INET6, src_info.ip, &bind_ipv6.sin6_addr) <= 0)
		{
			free_dst_addr_struct(dst);
			close(sfd);
			return SOCKET_ERROR;
		}

		bind_ptr = (struct sockaddr *)&bind_ipv6;
		bind_ptr_len = sizeof(struct sockaddr_in6);
	}

	rv = bind(sfd, bind_ptr, bind_ptr_len);
	if (rv == -1)
	{
		perror("bind");
		free_dst_addr_struct(dst);
		close(sfd);
		return SOCKET_ERROR;
	}

	/* Declare header and init all fields to 0 */
	tcp_header_t tcp_hdr;
	memset(&tcp_hdr, 0, sizeof(tcp_header_t));
	tcp_hdr.sport = htons(src_info.port);
	tcp_hdr.seq = htonl(arc4random()); /* rand is oboleted by this function */
	tcp_hdr.ack = htonl(0);
	tcp_hdr.offset_rsrvd.bits.offset = 5;
	tcp_hdr.offset_rsrvd.bits.reserved = 0;
	tcp_hdr.flags |= SYN;
	tcp_hdr.window = htons(1024); /* Change to random later? */

	/* Fill in pseudo header depending on the address family of the target */
	tcp_pseudo_ipv4_t tcp_pseudo_ipv4;
	tcp_pseudo_ipv6_t tcp_pseudo_ipv6;
	if (dst->ai_family == AF_INET)
	{
		memset(&tcp_pseudo_ipv4, 0, sizeof(tcp_pseudo_ipv4_t));
		tcp_pseudo_ipv4.src_ip = ((struct sockaddr_in *)bind_ptr)->sin_addr.s_addr;
		tcp_pseudo_ipv4.dst_ip = ((struct sockaddr_in *)(dst->ai_addr))->sin_addr.s_addr;
		tcp_pseudo_ipv4.ptcl = protocol->p_proto;
		tcp_pseudo_ipv4.tcp_len = htons(sizeof(tcp_header_t));

		/*printf("TCP pseudo header len: %d\n", ntohs(tcp_pseudo_ipv4.tcp_len));
		printf("Raw Packet (TCP Pseudo Header):\n");
		for (size_t i = 0; i < sizeof(tcp_pseudo_ipv4_t); i++)
		{
			printf("%02x ", ((unsigned char *)&tcp_pseudo_ipv4)[i]);
			if ((i + 1) % 16 == 0)
			{
				printf("\n");
			}
		}
		printf("\n");*/

		// TODO Change this
		tcp_hdr.dport = htons(8000);

		/*printf("Raw Packet (TCP Header Before Checksum):\n");
		for (size_t i = 0; i < sizeof(tcp_header_t); i++)
		{
			printf("%02x ", ((unsigned char *)&tcp_hdr)[i]);
			if ((i + 1) % 16 == 0)
			{
				printf("\n");
			}
		}
		printf("\n");*/

		/* Calculate checksum */
		size_t checksum_len = sizeof(tcp_header_t) + sizeof(tcp_pseudo_ipv4_t);
		u_int8_t *checksum_buf = malloc(checksum_len);
		if (checksum_buf == NULL)
		{
			free_dst_addr_struct(dst);
			close(sfd);
			return MEM_ALLOC_ERROR;
		}

		/* Copy pseudo header and TCP header into a buffer */
		u_int8_t *temp = checksum_buf;
		memcpy(temp, &tcp_pseudo_ipv4, sizeof(tcp_pseudo_ipv4_t));
		memcpy(temp + sizeof(tcp_pseudo_ipv4_t), &tcp_hdr, sizeof(tcp_header_t));

		/*printf("Raw Packet (Checksum buffer):\n");
		for (size_t i = 0; i < checksum_len; i++)
		{
			printf("%02x ", ((unsigned char *)temp)[i]);
			if ((i + 1) % 16 == 0)
			{
				printf("\n");
			}
		}
		printf("\n");*/

		tcp_hdr.checksum = calc_checksum(checksum_buf, checksum_len);
		// printf("Checksum for TCP header: %d\n", ntohs(tcp_hdr.checksum));

		// printf("TCP pseudo header len: %d\n", ntohs(tcp_pseudo_ipv4.tcp_len));
		/*printf("Raw Packet (TCP Header):\n");
		for (size_t i = 0; i < sizeof(tcp_header_t); i++)
		{
			printf("%02x ", ((unsigned char *)&tcp_hdr)[i]);
			if ((i + 1) % 16 == 0)
			{
				printf("\n");
			}
		}
		printf("\n");*/

		// TODO ADD IP HEADER
		struct ip ip_header;
		memset(&ip_header, 0, sizeof(struct ip));
		ip_header.ip_dst = ((struct sockaddr_in *)(dst->ai_addr))->sin_addr;
		ip_header.ip_src = ((struct sockaddr_in *)bind_ptr)->sin_addr;
		ip_header.ip_v = 4;	 /* Version 4 */
		ip_header.ip_hl = 5; /* Header length, no options */
		ip_header.ip_len = htons(sizeof(struct ip) + sizeof(tcp_header_t));
		ip_header.ip_id = htons(arc4random() & 0xffff); /* 16 bits */
		ip_header.ip_ttl = 64;							/* Mac and Linux default */
		ip_header.ip_p = (u_char)protocol->p_proto;		/* TCP */
		ip_header.ip_sum = htons(0);
		ip_header.ip_sum = htons(calc_checksum(&ip_header, sizeof(struct ip)));

		struct ip_packet
		{
			struct ip ip_hdr;
			tcp_header_t tcp_hdr;
		};

		/*printf("IP Checksum: %d\n", ntohs(ip_header.ip_sum));
		printf("Raw Packet (IP Header):\n");
		for (size_t i = 0; i < sizeof(struct ip); i++)
		{
			printf("%02x ", ((unsigned char *)&ip_header)[i]);
			if ((i + 1) % 16 == 0)
			{
				printf("\n");
			}
		}
		printf("\n");*/

		struct ip_packet ip_pkt = {
			.ip_hdr = ip_header,
			.tcp_hdr = tcp_hdr,
		};

		/*printf("TCP Checksum: %d\n", ntohs(tcp_hdr.checksum));
		printf("Raw Packet (IP Header + TCP Header):\n");
		for (size_t i = 0; i < sizeof(struct ip_packet); i++)
		{
			printf("%02x ", ((unsigned char *)&ip_pkt)[i]);
			if ((i + 1) % 16 == 0)
			{
				printf("\n");
			}
		}
		printf("\n");*/

		// send to first port
		struct sockaddr_in *dest_ip_and_port = ((struct sockaddr_in *)dst->ai_addr);
		dest_ip_and_port->sin_port = tcp_hdr.dport;
		dest_ip_and_port->sin_family = AF_INET;

		printf("Destination IP: %s\n", inet_ntoa(dest_ip_and_port->sin_addr));
		printf("Destination Port: %d\n", ntohs(dest_ip_and_port->sin_port));

		/*rv = connect(sfd, dst->ai_addr, dst->ai_addrlen);
		if (rv != 0)
		{
			free_dst_addr_struct(dst);
			perror("connect");
			close(sfd);
			return SOCKET_ERROR;
		}*/

		size_t packet_len = sizeof(struct ip) + sizeof(tcp_header_t);
		/*u_int8_t *send_buf = malloc(packet_len);
		if (send_buf == NULL)
		{
			free_dst_addr_struct(dst);
			free(checksum_buf);
			free(src_info.ip);
			perror("sendto");
			close(sfd);
			return SOCKET_ERROR;
		}
		memset(send_buf, 0, packet_len);
		memcpy(send_buf, &ip_pkt.ip_hdr, sizeof(struct ip));
		memcpy(send_buf + sizeof(struct ip), &ip_pkt.tcp_hdr, sizeof(tcp_header_t));*/

		ssize_t bytes_left = sizeof(tcp_header_t);
		/*printf("Raw Packet (Send buf):\n");
		for (size_t i = 0; i < packet_len; i++)
		{
			printf("%02x ", ((unsigned char *)&send_buf)[i + 32]);
			if ((i + 1) % 16 == 0)
			{
				printf("\n");
			}
		}
		printf("\n");*/

		ssize_t total_sent = 0;
		ssize_t sent;
		while (total_sent < bytes_left)
		{
			sent = sendto(sfd, &tcp_hdr + total_sent, bytes_left - total_sent, 0,
						  dst->ai_addr,
						  dst->ai_addrlen);
			if (sent == -1)
			{
				free_dst_addr_struct(dst);
				free(checksum_buf);
				perror("sendto");
				close(sfd);
				return SOCKET_ERROR;
			}
			printf("SENT: %zd\n", sent);
			total_sent += sent;
		}

		// TODO USE LIBPCAP ON MAC. THE OS SEEMS TO INTERCEPT ALL MESSAGES COMING IN

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

			// TODO ADD MORE CHECKS

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
		/*memset(&tcp_pseudo_ipv6, 0, sizeof(tcp_pseudo_ipv6_t));
		tcp_pseudo_ipv6.src_ip = s_addr_in6->sin6_addr;
		tcp_pseudo_ipv6.dst_ip = ((struct sockaddr_in6 *)(dst->ai_addr))->sin6_addr;
		tcp_pseudo_ipv6.next = protocol->p_proto;
		tcp_pseudo_ipv6.length = htonl(sizeof(tcp_header_t));*/
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
