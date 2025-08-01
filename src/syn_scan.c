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
#include <limits.h>

#include "../include/utils.h"
#include "../include/error.h"
#include "../include/headers.h"

#include <pcap/pcap.h> /* Read packets */

#include <signal.h> /* Alarm to break pcap_loop */
#include <unistd.h> /* alarm() */

#include <pthread.h>
#include <stdint.h>

#define SYN 0x02	 /* Sets the SYN flag in the TCP flag field */
#define SYN_ACK 0x12 /* Sets the SYN and ACK flag in the TCP flag field */
#define RST 0x04	 /* Sets the RST flag in the TCP flag field */
#define TIMEOUT_SECONDS 2
#define RETRIES 3
#define IP_PACKET_LEN 65535
#define CAP_TIMEOUT 10 /* Milliseconds */
#define ALARM_SEC 2
#define ETH_TYPE_IP 0x0800
#define IP_PROTO_TCP 0x06
#define REALLOC_SIZE 1024

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
	// short port_status;
	short loopback_flag;
	short port_status[65536];
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
	struct callback_data *c_data = (struct callback_data *)user;

	/* If loopback */
	if (c_data->loopback_flag)
	{
		int skip_null = 4;
		struct ip *ip_hdr = (struct ip *)(bytes + skip_null);
		if (ip_hdr->ip_p != IP_PROTO_TCP)
		{
			return;
		}
		int ip_len = ip_hdr->ip_hl * 4;
		tcp_header_t *tcp_hdr = (tcp_header_t *)(bytes + skip_null + ip_len);

		if (tcp_hdr->flags != SYN_ACK)
		{
			return;
		}

		if (ntohs(tcp_hdr->sport) == 4444)
			printf("4444\n");

		if (ntohs(tcp_hdr->sport) == 65535)
			printf("65535\n");

		c_data->port_status[ntohs(tcp_hdr->sport)] = 1;
		return;
		// pcap_breakloop(handle);
	}

	/* Else */

	if (pkt_hdr->caplen < (sizeof(ethernet_header_t) +
						   sizeof(struct ip) +
						   sizeof(tcp_header_t)))
	{
		return;
	}

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
		(tcp_header_t *)(bytes + sizeof(ethernet_header_t) + ip_len);
	if (tcp_hdr->flags != SYN_ACK)
	{
		return;
	}

	c_data->port_status[ntohs(tcp_hdr->sport)] = 1;
	return;
	// pcap_breakloop(handle);
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

/**
 * @brief Parses a string with a format similar to `"1,2,3-5,6"`, and returns it
 * as an int array `[1,2,3,4,5,6]`. The returned array should be freed with
 * `free()`.
 *
 * @param port_str The string to parse.
 * @param port_count int to store the number of ports in.
 * @return int* array.
 */
unsigned short *parse_ports(const char *port_str, int *port_count)
{
	unsigned short seen_ports[65536] = {0};
	char *copy = strdup(port_str);
	if (copy == NULL)
	{
		return NULL;
	}

	char *copy_to_free = copy;
	char *token;
	unsigned short *ports = NULL;
	int count = 0;

	while ((token = strsep(&copy, ",")) != NULL)
	{
		/* Skip ,, */
		if (*token == '\0')
		{
			continue;
		}

		/* Range of ports */
		int lower, upper;
		if (strchr(token, '-') != NULL)
		{
			/* Continue if invalid numbers */
			if (sscanf(token, "%d-%d", &lower, &upper) != 2)
			{
				continue;
			}
			/* Set lower port to 1 if negative */
			if (!lower)
			{
				lower = 1;
			}

			/* Set upper port to highest valid, if outside bound */
			if (upper > 65535)
			{
				upper = 65535;
			}

			for (int i = lower; i <= upper; i++)
			{
				/* Skip already added port or add it */
				if (seen_ports[i])
				{
					continue;
				}
				seen_ports[i] = 1;

				unsigned short *temp = realloc(ports, sizeof(unsigned short) * (count + REALLOC_SIZE));
				if (temp == NULL)
				{
					free(ports);
					free(copy_to_free);
					return NULL;
				}
				ports = temp;
				ports[count++] = i;
			}
		}
		/* Single port */
		else
		{
			/* Skip if not valid number */
			char *endptr;
			if (!strtol(token, &endptr, 10) || *endptr != '\0')
			{
				continue;
			}

			int converted = atoi(token);
			if (converted <= 0)
			{
				converted = 1;
			}

			if (converted > 65535)
			{
				converted = 65535;
			}

			/* Skip already added port or add it */
			if (seen_ports[converted])
			{
				continue;
			}
			seen_ports[converted] = 1;

			unsigned short *temp = realloc(ports, sizeof(unsigned short) * (count + 1));
			if (temp == NULL)
			{
				free(ports);
				free(copy_to_free);
				return NULL;
			}
			ports = temp;
			ports[count++] = converted;
		}
	}

	free(copy_to_free);
	*port_count = count;
	return ports;
}

void *capture_thread(void *arg)
{
	int rv = pcap_loop(handle, 0, tcp_process_pkt, (u_char *)arg);
	if (rv == PCAP_ERROR)
	{
		pcap_close(handle);
		return (void *)(intptr_t)PCAP_LOOP;
	}

	return (void *)(intptr_t)SUCCESS;
}

int port_scan(char *address, unsigned short *port_arr, int port_count, int print_state)
{
	printf("Scanning %d ports on %s...\n", port_count, address);

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
	// tcp_pseudo_ipv6_t tcp_pseudo_ipv6;
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

		/*handle = pcap_create(if_name->name, errbuf);
		pcap_set_snaplen(handle, IP_PACKET_LEN);
		pcap_set_promisc(handle, 0);
		pcap_set_timeout(handle, CAP_TIMEOUT);
		pcap_set_buffer_size(handle, 40 * 1024 * 1024);
		pcap_activate(handle);*/

		struct bpf_program filter;
		char filter_expr[128];
		if (snprintf(filter_expr, sizeof(filter_expr),
					 "src %s and dst %s and dst port %d",
					 address,
					 src_info.ip,
					 ntohs(tcp_hdr.sport)) < 0)
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

		struct callback_data c_data = {0};
		if (strncmp("127.0.0.1", address, 10) == 0)
		{
			c_data.loopback_flag = 1;
		}

		/* Start capture in a separate thread */
		pthread_t thread;
		pthread_create(&thread, NULL, capture_thread, &c_data);

		for (int p_index = 0; p_index < port_count; p_index++)
		{
			// printf("Scanning port: %d\n", port_arr[p_index]);
			if (port_arr[p_index] <= 0)
			{
				continue;
			}

			memset(&tcp_hdr, 0, sizeof(tcp_header_t));
			tcp_hdr.sport = htons(src_info.port);
			tcp_hdr.seq = htonl(arc4random()); /* rand is oboleted by this function */
			tcp_hdr.ack = htonl(0);
			tcp_hdr.offset_rsrvd.bits.offset = 5;
			tcp_hdr.offset_rsrvd.bits.reserved = 0;
			tcp_hdr.flags |= SYN;
			tcp_hdr.window = htons(1024); /* Change to random later? */
			tcp_hdr.dport = htons(port_arr[p_index]);

			/* Copy pseudo header and TCP header into a buffer */
			u_int8_t *temp = checksum_buf;
			memcpy(temp, &tcp_pseudo_ipv4, sizeof(tcp_pseudo_ipv4_t));
			memcpy(temp + sizeof(tcp_pseudo_ipv4_t), &tcp_hdr, sizeof(tcp_header_t));

			tcp_hdr.checksum = calc_checksum(checksum_buf, checksum_len);

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
			usleep(500);
		}

		/* Stop sniff if timeout */
		signal(SIGALRM, break_capture);

		/* Start capture timer */
		alarm(ALARM_SEC);

		/* Remove thread */
		void *thread_val;
		pthread_join(thread, &thread_val);
		if ((int)(intptr_t)thread_val != 0)
		{
			return PCAP_LOOP;
		}

		signal(SIGALRM, SIG_DFL);

		// TODO Remove print
		if (print_state)
			printf("PORT\tSTATE\n");

		for (int p_index = 0; p_index < port_count; p_index++)
		{
			// printf("Port: %d, %d\n", port_arr[p_index], c_data.port_status[port_arr[p_index]]);
			//  TODO: Write results to file if specified
			if (print_state)
			{
				if (c_data.port_status[port_arr[p_index]])
				{
					printf("%d\tOPEN\n", port_arr[p_index]);
				}
				else
				{
					// printf("%d\tCLOSED\n", port_arr[p_index]);
				}
			}
		}

		// free
		free(checksum_buf);
		pcap_close(handle);
		pcap_freealldevs(alldevs);

		return SUCCESS;
	}
	else if (dst->ai_family == AF_INET6)
	{
		// TODO

		return NO_RESPONSE;
	}
	else
	{
		// error
	}

	// TODO CHECK FREEING OF ALLOCATED BUFFERS
	free(src_info.ip);
	free_dst_addr_struct(dst);
	close(sfd);

	return SUCCESS;
}
