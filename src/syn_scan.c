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

#include <pcap/pcap.h> /* Read packets */

#include <signal.h> /* Alarm to break pcap_loop */
#include <unistd.h> /* alarm() */

#define SYN 0x02	 /* Sets the SYN flag in the TCP flag field */
#define SYN_ACK 0x12 /* Sets the SYN and ACK flag in the TCP flag field */
#define RST 0x04	 /* Sets the RST flag in the TCP flag field */
#define TIMEOUT_SECONDS 2
#define RETRIES 3
#define IP_PACKET_LEN 65535
#define CAP_TIMEOUT 1000 /* Milliseconds */
#define ALARM_SEC 2
#define ETH_TYPE_IP 0x0800
#define IP_PROTO_TCP 0x06

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

/* pcap struct to store info from callback function */
struct callback_data
{
	short port_status;
};

static pcap_t *handle;

static void break_capture(int signum)
{
	(void)signum;
	pcap_breakloop(handle);
	return;
}

/* Callback function for processing the received frames */
void tcp_process_pkt(u_char *user, const struct pcap_pkthdr *pkt_hdr,
					 const u_char *bytes)
{
	if (pkt_hdr->caplen < (sizeof(ethernet_header_t) +
						   sizeof(struct ip) +
						   sizeof(tcp_header_t)))
	{
		return;
	}

	struct callback_data *c_data = (struct callback_data *)user;
	ethernet_header_t *eth = (ethernet_header_t *)bytes;
	if (ntohs(eth->ptype) != ETH_TYPE_IP)
	{
		return;
	}
	struct ip *ip_hdr = (struct ip *)(bytes + sizeof(ethernet_header_t));
	if (ip_hdr->ip_p != IP_PROTO_TCP)
	{
		return;
	}
	int ip_len = ip_hdr->ip_hl * 4;
	tcp_header_t *tcp_hdr =
		(struct tcp_header_t *)(bytes + sizeof(ethernet_header_t) + ip_len);
	if (tcp_hdr->flags != SYN_ACK)
	{
		return;
	}

	c_data->port_status = 1;
	pcap_breakloop(handle);
}

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

int port_scan(char *address, short plower, short pupper)
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

		memset(&tcp_pseudo_ipv4, 0, sizeof(tcp_pseudo_ipv4_t));
		tcp_pseudo_ipv4.src_ip = ((struct sockaddr_in *)bind_ptr)->sin_addr.s_addr;
		tcp_pseudo_ipv4.dst_ip = ((struct sockaddr_in *)(dst->ai_addr))->sin_addr.s_addr;
		tcp_pseudo_ipv4.ptcl = protocol->p_proto;
		tcp_pseudo_ipv4.tcp_len = htons(sizeof(tcp_header_t));

		/* Calculate checksum */
		size_t checksum_len = sizeof(tcp_header_t) + sizeof(tcp_pseudo_ipv4_t);
		u_int8_t *checksum_buf = malloc(checksum_len);
		if (checksum_buf == NULL)
		{
			free_dst_addr_struct(dst);
			close(sfd);
			return MEM_ALLOC_ERROR;
		}

		pcap_if_t *alldevs;
		for (short p = plower; p <= pupper; p++)
		{
			// TODO Change this
			memset(&tcp_hdr, 0, sizeof(tcp_header_t));
			tcp_hdr.sport = htons(src_info.port);
			tcp_hdr.seq = htonl(arc4random()); /* rand is oboleted by this function */
			tcp_hdr.ack = htonl(0);
			tcp_hdr.offset_rsrvd.bits.offset = 5;
			tcp_hdr.offset_rsrvd.bits.reserved = 0;
			tcp_hdr.flags |= SYN;
			tcp_hdr.window = htons(1024); /* Change to random later? */
			tcp_hdr.dport = htons(p);

			/* Copy pseudo header and TCP header into a buffer */
			u_int8_t *temp = checksum_buf;
			memcpy(temp, &tcp_pseudo_ipv4, sizeof(tcp_pseudo_ipv4_t));
			memcpy(temp + sizeof(tcp_pseudo_ipv4_t), &tcp_hdr, sizeof(tcp_header_t));

			tcp_hdr.checksum = calc_checksum(checksum_buf, checksum_len);

			// send to first port
			struct sockaddr_in *dest_ip_and_port = ((struct sockaddr_in *)dst->ai_addr);
			dest_ip_and_port->sin_port = tcp_hdr.dport;
			dest_ip_and_port->sin_family = AF_INET;

			ssize_t bytes_left = sizeof(tcp_header_t);
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
				total_sent += sent;
			}

			// TODO USE LIBPCAP ON MAC. THE OS SEEMS TO INTERCEPT ALL MESSAGES COMING IN
			/* Initialize library */
			char errbuf[PCAP_ERRBUF_SIZE];
			int rv = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
			if (rv != 0)
			{
				return PCAP_INIT;
			}

			/* Get capture interface */
			if (pcap_findalldevs(&alldevs, errbuf) == -1)
			{
				fprintf(stderr, "Error: %s\n", errbuf);
				return IFACE_ERROR;
			}

			struct pcap_if *if_name = NULL;
			char *if_ip = src_info.ip;

			for (pcap_if_t *d = alldevs; d; d = d->next)
			{
				for (pcap_addr_t *a = d->addresses; a; a = a->next)
				{
					if (a->addr && a->addr->sa_family == AF_INET)
					{
						struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
						if (strcmp(inet_ntoa(sin->sin_addr), if_ip) == 0)
						{
							if_name = d;
							break;
						}
					}
				}
				if (if_name)
				{
					break;
				}
			}

			if (!if_name)
			{
				return IFACE_ERROR;
			}

			handle = pcap_open_live(if_name->name, IP_PACKET_LEN, 0, CAP_TIMEOUT, errbuf);
			if (handle == NULL)
			{
				/* Check if the error occured because of insufficient privileges */
				if (strstr(errbuf, "Operation not permitted"))
				{
					return PERMISSION_ERROR;
				}
				return PCAP_OPEN;
			}

			struct bpf_program filter;
			char filter_expr[128];
			if (snprintf(filter_expr, sizeof(filter_expr),
						 "src %s and dst %s and src port %d and dst port %d",
						 address,
						 src_info.ip,
						 ntohs(tcp_hdr.dport),
						 ntohs(tcp_hdr.sport)) < 0)
			// TODO Add loopback support
			{
				pcap_close(handle);
				return PCAP_FILTER;
			}

			rv = pcap_compile(handle, &filter, filter_expr, 0, 0);
			if (rv != 0)
			{
				pcap_perror(handle, "Compile");
				pcap_close(handle);
				return PCAP_FILTER;
			}

			rv = pcap_setfilter(handle, &filter);
			if (rv != 0)
			{
				pcap_close(handle);
				return PCAP_FILTER;
			}

			struct callback_data c_data = {.port_status = 0};

			/* Stop sniff if timeout */
			signal(SIGALRM, break_capture);

			/* Start capture timer */
			alarm(ALARM_SEC);

			rv = pcap_loop(handle, 0, tcp_process_pkt, (u_char *)&c_data);
			if (rv == PCAP_ERROR)
			{
				pcap_close(handle);
				return PCAP_LOOP;
			}

			signal(SIGALRM, SIG_DFL);

			if (c_data.port_status)
			{
				printf("PORT %d OPEN!\n", ntohs(tcp_hdr.dport));
				// return SUCCESS;
			}
			else
			{
				printf("PORT %d NOT OPEN!\n", ntohs(tcp_hdr.dport));
			}
		}
		// print or save results

		// change port number and maybe src port

		// recalculate checksum

		// send and repeat

		// free
		free(checksum_buf);
		pcap_close(handle);
		pcap_freealldevs(alldevs);

		return SUCCESS;
	}
	else if (dst->ai_family == AF_INET6)
	{
		/*memset(&tcp_pseudo_ipv6, 0, sizeof(tcp_pseudo_ipv6_t));
		tcp_pseudo_ipv6.src_ip = s_addr_in6->sin6_addr;
		tcp_pseudo_ipv6.dst_ip = ((struct sockaddr_in6 *)(dst->ai_addr))->sin6_addr;
		tcp_pseudo_ipv6.next = protocol->p_proto;
		tcp_pseudo_ipv6.length = htonl(sizeof(tcp_header_t));*/

		return NO_RESPONSE;
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

	// TODO CHECK FREEING OF ALLOCATED BUFFERS
	free(src_info.ip);
	free_dst_addr_struct(dst);
	close(sfd);

	return SUCCESS;
}
