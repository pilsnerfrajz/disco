#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <unistd.h>
#include <limits.h>

#include "../include/utils.h"
#include "../include/error.h"
#include "../include/headers.h"
#include "../include/syn_scan.h"

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
#define CAP_TIMEOUT 100 /* Milliseconds */
#define ALARM_SEC 2
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD
#define IP_PROTO_TCP 0x06
#define REALLOC_SIZE 1024
#define CHECKSUM_LEN_IPV4 (sizeof(tcp_header_t) + sizeof(tcp_pseudo_ipv4_t))
#define CHECKSUM_LEN_IPV6 (sizeof(tcp_header_t) + sizeof(tcp_pseudo_ipv6_t))

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

/* Global flag to enable output during testing */
static int test_print = 0;

struct src_info
{
	char *ip;
	u_int16_t port;
};

/* pcap struct to store info from callback function */
struct callback_data
{
	short loopback_flag;
	short any_open; /* Flag if any open port is found */
	volatile short port_status[65536];
};

static pcap_t *handle;

static void break_capture(int signum)
{
	(void)signum;
	pcap_breakloop(handle);
	return;
}

/* Callback function for processing the received frames */
static void tcp_process_pkt(u_char *user, const struct pcap_pkthdr *pkt_hdr,
							const u_char *bytes)
{
	struct callback_data *c_data = (struct callback_data *)user;
	tcp_header_t *tcp_hdr;

	/* If loopback */
	if (c_data->loopback_flag)
	{
		int skip_null = 4;
		struct ip *ip_hdr = (struct ip *)(bytes + skip_null);

		/* Check if IPv4 */
		if (ip_hdr->ip_v == 4 && ip_hdr->ip_p == IP_PROTO_TCP)
		{
			int ip_len = ip_hdr->ip_hl * 4;
			tcp_hdr = (tcp_header_t *)(bytes + skip_null + ip_len);
		}
		/* Check if IPv6 */
		else if (ip_hdr->ip_v == 6)
		{
			struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(bytes + skip_null);
			if (ip6_hdr->ip6_nxt == IP_PROTO_TCP)
			{
				tcp_hdr = (tcp_header_t *)(bytes + skip_null + sizeof(struct ip6_hdr));
			}
			else
			{
				return;
			}
		}
		else
		{
			/* Invalid IP version */
			return;
		}
	}
	else
	{
		/* Check minimum packet size for IPv4 */
		if (pkt_hdr->caplen < (sizeof(ethernet_header_t) +
							   sizeof(struct ip) +
							   sizeof(tcp_header_t)))
		{
			return;
		}

		ethernet_header_t *eth = (ethernet_header_t *)bytes;

		/* Handle IPv4 packets */
		if (ntohs(eth->ptype) == ETH_TYPE_IPV4)
		{
			struct ip *ip_hdr = (struct ip *)(bytes + sizeof(ethernet_header_t));
			if (ip_hdr->ip_p != IP_PROTO_TCP)
			{
				return;
			}
			int ip_len = ip_hdr->ip_hl * 4;
			tcp_hdr = (tcp_header_t *)(bytes + sizeof(ethernet_header_t) + ip_len);
		}
		/* Handle IPv6 packets */
		else if (ntohs(eth->ptype) == ETH_TYPE_IPV6)
		{
			/* Check minimum packet size for IPv6 */
			if (pkt_hdr->caplen < (sizeof(ethernet_header_t) +
								   sizeof(struct ip6_hdr) +
								   sizeof(tcp_header_t)))
			{
				return;
			}

			struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(bytes + sizeof(ethernet_header_t));
			if (ip6_hdr->ip6_nxt != IP_PROTO_TCP)
			{
				return;
			}
			tcp_hdr = (tcp_header_t *)(bytes + sizeof(ethernet_header_t) + sizeof(struct ip6_hdr));
		}
		else
		{
			/* Invalid protocol type */
			return;
		}
	}

	if (tcp_hdr->flags == SYN_ACK)
	{
		c_data->port_status[ntohs(tcp_hdr->sport)] = OPEN;
		c_data->any_open = 1;
	}
	else if (tcp_hdr->flags & RST)
	{
		c_data->port_status[ntohs(tcp_hdr->sport)] = CLOSED;
	}
	return;
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
static int get_src_info(struct addrinfo *dst, struct src_info *src_info)
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
		// TODO error
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

/**
 * @brief Gets the address and port from the `src_info` struct and prepares
 * it for use in `bind()`. The `bind_ptr` parameter points to the address
 * structure to bind to. The `bind_ptr_len` parameter stores the length of the
 * address structure, needed in the `bind()` call.
 *
 * @param bind_ptr Pointer to the address structure to bind to.
 * @param bind_ptr_len Pointer to store the length of the address structure.
 * @param dst Destination address information.
 * @param src_info Source address information.
 * @param bind_ipv4 IPv4 bind address structure.
 * @param bind_ipv6 IPv6 bind address structure.
 * @return `int` Returns 0 on success. SOCKET_ERROR is returned if an error occurs.
 */
static int get_bind_addr(struct sockaddr **bind_ptr,
						 socklen_t *bind_ptr_len,
						 struct addrinfo *dst,
						 struct src_info *src_info,
						 struct sockaddr_in *bind_ipv4,
						 struct sockaddr_in6 *bind_ipv6)
{
	if (dst->ai_family == AF_INET)
	{
		memset(bind_ipv4, 0, sizeof(struct sockaddr_in));
		bind_ipv4->sin_family = AF_INET;
		bind_ipv4->sin_port = htons(src_info->port);
		if (inet_pton(AF_INET, src_info->ip, &bind_ipv4->sin_addr) <= 0)
		{
			return SOCKET_ERROR;
		}

		*bind_ptr = (struct sockaddr *)bind_ipv4;
		*bind_ptr_len = sizeof(struct sockaddr_in);
	}
	else if (dst->ai_family == AF_INET6)
	{
		memset(bind_ipv6, 0, sizeof(struct sockaddr_in6));
		bind_ipv6->sin6_family = AF_INET6;
		bind_ipv6->sin6_port = htons(src_info->port);
		if (inet_pton(AF_INET6, src_info->ip, &bind_ipv6->sin6_addr) <= 0)
		{
			return SOCKET_ERROR;
		}

		*bind_ptr = (struct sockaddr *)bind_ipv6;
		*bind_ptr_len = sizeof(struct sockaddr_in6);
	}
	return 0;
}

void set_test_print_flag(int enable)
{
	test_print = enable;
}

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

/**
 * @brief Thread function for capturing packets with `pcap_loop()`.
 *
 * @param arg Pointer to the argument passed to the thread.
 * @return `void*`. Cast to int with `(int)(intptr_t)` to check the return value.
 */
static void *capture_thread(void *arg)
{
	int rv = pcap_loop(handle, 0, tcp_process_pkt, (u_char *)arg);
	if (rv == PCAP_ERROR)
	{
		pcap_close(handle);
		return (void *)(intptr_t)PCAP_LOOP;
	}
	return (void *)(intptr_t)SUCCESS;
}

/**
 * @brief Helper function for freeing allocated memory.
 *
 * @param dst
 * @param sfd Socket file descriptor
 * @param handle pcap handle
 * @param checksum_buf buffer for storing packet checksums
 * @param src_info Source port and address information
 */
static void cleanup(struct addrinfo *dst, int sfd, pcap_t *handle,
					u_int8_t *checksum_buf, struct src_info *src_info)
{
	free_dst_addr_struct(dst);
	free(checksum_buf);
	close(sfd);
	if (handle)
	{
		pcap_close(handle);
	}
	if (src_info && src_info->ip)
	{
		free(src_info->ip);
	}
}

/**
 * @brief Setup for a pcap handle. Initiates a packet capture on the correct
 * network interface based on the source address in `src_info` and allocates
 * memory for the capture buffer.
 *
 * @param h Pointer to the pcap handle
 * @param src_info Source port and address information
 * @return `int` 0 on success or an error found in `error.h` if an error occurs.
 */
static int pcap_handle_setup(pcap_t **h, struct src_info src_info)
{
	/* Initialize library */
	char errbuf[PCAP_ERRBUF_SIZE];
	int rv = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
	if (rv != 0)
	{
		return PCAP_INIT;
	}

	pcap_if_t *alldevs = NULL;
	/* Get capture interface */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		if (alldevs)
		{
			pcap_freealldevs(alldevs);
		}
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
			else if (a->addr && a->addr->sa_family == AF_INET6)
			{
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)a->addr;
				char ipv6_str[INET6_ADDRSTRLEN];
				if (inet_ntop(AF_INET6, &sin6->sin6_addr, ipv6_str, INET6_ADDRSTRLEN))
				{
					if (strcmp(ipv6_str, if_ip) == 0)
					{
						if_name = d;
						break;
					}
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
		if (alldevs)
		{
			pcap_freealldevs(alldevs);
		}
		return IFACE_ERROR;
	}

	*h = pcap_create(if_name->name, errbuf);
	if (*h == NULL)
	{
		if (alldevs)
		{
			pcap_freealldevs(alldevs);
		}
		/* Check if the error occured because of insufficient privileges */
		if (strstr(errbuf, "Operation not permitted"))
		{
			return PERMISSION_ERROR;
		}
		return PCAP_OPEN;
	}

	if (alldevs)
	{
		pcap_freealldevs(alldevs);
	}

	if (pcap_set_snaplen(*h, IP_PACKET_LEN) != 0)
	{
		goto handle_cleanup;
	}

	if (pcap_set_promisc(*h, 0) != 0)
	{
		goto handle_cleanup;
	}

	if (pcap_set_immediate_mode(*h, 1) != 0)
	{
		goto handle_cleanup;
	}

	if (pcap_set_timeout(*h, CAP_TIMEOUT) != 0)
	{
		goto handle_cleanup;
	}

	if (pcap_set_buffer_size(*h, 5000000) != 0)
	{
		goto handle_cleanup;
	}

	rv = pcap_activate(*h);
	if (rv != 0)
	{
		if (rv == PCAP_ERROR_PERM_DENIED)
		{
			pcap_close(*h);
			*h = NULL;
			return PERMISSION_ERROR;
		}
		else if (rv < 0)
		{
			goto handle_cleanup;
		}
		// TODO Log warnings if rv > 0?
	}
	return 0;

handle_cleanup:
	pcap_close(*h);
	*h = NULL;
	return PCAP_OPEN;
}

/**
 * @brief Setup a packet filter for the pcap handle. The current filter looks
 * for packets coming from the scanned host, destined for the scanning host and
 * the source port used to send SYN packets.
 *
 * @param address The IP address of the scanned host to filter on.
 * @param src_info Source port and address information of scanner.
 * @return `int` 0 on success or an error found in `error.h` if an error occurs.
 */
static int pcap_filter_setup(char *address, struct src_info src_info)
{
	struct bpf_program filter;
	char filter_expr[256];
	if (snprintf(filter_expr, sizeof(filter_expr),
				 "src %s and dst %s and dst port %d and tcp",
				 address, src_info.ip,
				 src_info.port) < 0)
	{
		return PCAP_FILTER;
	}

	int rv = pcap_compile(handle, &filter, filter_expr, 0, 0);
	if (rv != 0)
	{
		return PCAP_FILTER;
	}

	rv = pcap_setfilter(handle, &filter);
	if (rv != 0)
	{
		return PCAP_FILTER;
	}
	return 0;
}

/**
 * @brief Creates a TCP pseudo header for IPv4 and stores it in the
 * `tcp_pseudo_ipv4` struct.
 *
 * @param tcp_pseudo_ipv4 Pseudo header struct to store result in.
 * @param bind_ptr Pointer to the local socket address.
 * @param dst Pointer to the destination address information.
 * @param protocol Pointer to the protocol information.
 */
static void create_ipv4_pseudo_hdr(tcp_pseudo_ipv4_t *tcp_pseudo_ipv4,
								   struct sockaddr *bind_ptr,
								   struct addrinfo *dst,
								   struct protoent *protocol)
{
	memset(tcp_pseudo_ipv4, 0, sizeof(tcp_pseudo_ipv4_t));
	tcp_pseudo_ipv4->src_ip = ((struct sockaddr_in *)bind_ptr)->sin_addr.s_addr;
	tcp_pseudo_ipv4->dst_ip = ((struct sockaddr_in *)(dst->ai_addr))->sin_addr.s_addr;
	tcp_pseudo_ipv4->ptcl = protocol->p_proto;
	tcp_pseudo_ipv4->tcp_len = htons(sizeof(tcp_header_t));
}

/**
 * @brief Creates a TCP pseudo header for IPv6 and stores it in the
 * `tcp_pseudo_ipv6` struct.
 *
 * @param tcp_pseudo_ipv6 Pseudo header struct to store result in.
 * @param bind_ptr Pointer to the local socket address.
 * @param dst Pointer to the destination address information.
 * @param protocol Pointer to the protocol information.
 */
static void create_ipv6_pseudo_hdr(tcp_pseudo_ipv6_t *tcp_pseudo_ipv6,
								   struct sockaddr *bind_ptr,
								   struct addrinfo *dst,
								   struct protoent *protocol)
{
	memset(tcp_pseudo_ipv6, 0, sizeof(tcp_pseudo_ipv6_t));
	tcp_pseudo_ipv6->src_ip = ((struct sockaddr_in6 *)bind_ptr)->sin6_addr;
	tcp_pseudo_ipv6->dst_ip = ((struct sockaddr_in6 *)(dst->ai_addr))->sin6_addr;
	tcp_pseudo_ipv6->next = protocol->p_proto;
	tcp_pseudo_ipv6->length = htons(sizeof(tcp_header_t));
}

/**
 * @brief Creates and stores a TCP header in the tcp_hdr parameter.
 *
 * @param tcp_hdr Pointer to the TCP header struct to populate.
 * @param src_info Source port and address information of scanner.
 * @param port Destination port to use in the TCP header.
 * @param checksum_buf Buffer to store the checksum calculation.
 * @param pseudo_header Pointer to the pseudo header information.
 * @param address_family Address family (AF_INET or AF_INET6).
 * @return `int` 0 on success, -1 if the address family is unsupported.
 */
static int create_tcp_hdr(tcp_header_t *tcp_hdr,
						  struct src_info src_info,
						  unsigned short port,
						  u_int8_t *checksum_buf,
						  void *pseudo_header,
						  int address_family)
{
	memset(tcp_hdr, 0, sizeof(tcp_header_t));
	tcp_hdr->sport = htons(src_info.port);
	tcp_hdr->seq = htonl(arc4random());
	tcp_hdr->ack = htonl(0);
	tcp_hdr->offset_rsrvd.bits.offset = 5;
	tcp_hdr->offset_rsrvd.bits.reserved = 0;
	tcp_hdr->flags |= SYN;
	tcp_hdr->window = htons(1024);
	tcp_hdr->dport = htons(port);

	/* Copy pseudo header and TCP header into buffer based on address family */
	u_int8_t *temp = checksum_buf;
	if (address_family == AF_INET)
	{
		memcpy(temp, pseudo_header, sizeof(tcp_pseudo_ipv4_t));
		memcpy(temp + sizeof(tcp_pseudo_ipv4_t), tcp_hdr, sizeof(tcp_header_t));
		tcp_hdr->checksum = calc_checksum(checksum_buf, CHECKSUM_LEN_IPV4);
		return 0;
	}
	else if (address_family == AF_INET6)
	{
		memcpy(temp, pseudo_header, sizeof(tcp_pseudo_ipv6_t));
		memcpy(temp + sizeof(tcp_pseudo_ipv6_t), tcp_hdr, sizeof(tcp_header_t));
		tcp_hdr->checksum = calc_checksum(checksum_buf, CHECKSUM_LEN_IPV6);
		return 0;
	}
	return -1;
}

/**
 * @brief Create and send TCP SYN packets. Retries are made up to `RETRIES`
 * times for ports that have not responded. The port statuses are stored in
 * the `c_data` struct.
 *
 * It is possible to add control over packet delay and retries later.
 *
 * @param sfd Socket file descriptor.
 * @param dst Destination address information.
 * @param tcp_hdr Pointer to the TCP header struct to populate.
 * @param pseudo_header Pointer to the pseudo header information.
 * @param c_data Pointer to the callback data struct.
 * @param port_count Number of ports to scan.
 * @param port_arr Array of ports to scan.
 * @param src_info Source port and address information of scanner.
 * @param checksum_buf Buffer for the checksum calculation.
 * @param address_family Address family (AF_INET or AF_INET6).
 * @param thread Capture thread to kill if an error occurs.
 * @return `int` 0 on success, SOCKET_ERROR if an error occurs.
 */
static int send_syn(int sfd,
					struct addrinfo *dst,
					tcp_header_t *tcp_hdr,
					void *pseudo_header,
					struct callback_data *c_data,
					int port_count,
					unsigned short *port_arr,
					struct src_info src_info,
					u_int8_t *checksum_buf,
					int address_family,
					pthread_t thread)
{
	for (int r = 0; r < RETRIES; r++)
	{
		for (int p_index = 0; p_index < port_count && p_index < 65536; p_index++)
		{
			if (port_arr[p_index] <= 0)
			{
				continue;
			}

			/* Skip if port has already responded (open or closed) */
			if (c_data->port_status[port_arr[p_index]] != FILTERED)
			{
				continue;
			}

			usleep(5000);

			if (create_tcp_hdr(tcp_hdr, src_info, port_arr[p_index],
							   checksum_buf, pseudo_header, address_family) != 0)
			{
				// TODO Error code if error occurs?
				continue;
			}

			ssize_t bytes_left = sizeof(tcp_header_t);
			ssize_t total_sent = 0;
			ssize_t sent;
			while (total_sent < bytes_left)
			{
				sent = sendto(sfd, (char *)tcp_hdr + total_sent,
							  bytes_left - total_sent, 0,
							  dst->ai_addr,
							  dst->ai_addrlen);
				if (sent == -1)
				{
					/* Break loop and wait for thread before cleanup */
					pcap_breakloop(handle);
					void *thread_val;
					pthread_join(thread, &thread_val);
					return SOCKET_ERROR;
				}
				total_sent += sent;
			}
		}
	}

	return 0;
}

int port_scan(char *address,
			  unsigned short *port_arr,
			  int port_count,
			  short *is_open_port,
			  unsigned short **result_arr)
{
	if (test_print)
	{
		printf("┌ Scanning %d ports on %s...\n", port_count, address);
	}

	struct addrinfo *dst = get_dst_addr_struct(address, SOCK_RAW);
	if (dst == NULL)
	{
		return UNKNOWN_HOST;
	}

	char resolved_address[INET6_ADDRSTRLEN];
	if (dst->ai_addr->sa_family == AF_INET)
	{
		inet_ntop(AF_INET, &((struct sockaddr_in *)dst->ai_addr)->sin_addr,
				  resolved_address, INET_ADDRSTRLEN);
		address = resolved_address;
	}
	else
	{
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)dst->ai_addr)->sin6_addr,
				  resolved_address, INET6_ADDRSTRLEN);
		address = resolved_address;
	}

	struct src_info src_info = {0};
	if (get_src_info(dst, &src_info) != 0)
	{
		free_dst_addr_struct(dst);
		if (src_info.ip)
		{
			free(src_info.ip);
		}
		return SRC_ADDR;
	}

	struct protoent *protocol = getprotobyname("tcp");
	if (protocol == NULL)
	{
		free_dst_addr_struct(dst);
		free(src_info.ip);
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
		cleanup(dst, sfd, handle, NULL, &src_info);
		return SOCKET_ERROR;
	}

	/* Create struct to use in `bind` */
	struct sockaddr *bind_ptr;
	socklen_t bind_ptr_len = 0;
	struct sockaddr_in bind_ipv4;
	struct sockaddr_in6 bind_ipv6;
	rv = get_bind_addr(&bind_ptr, &bind_ptr_len, dst, &src_info, &bind_ipv4, &bind_ipv6);
	if (rv != 0)
	{
		cleanup(dst, sfd, handle, NULL, &src_info);
		return rv;
	}

	rv = bind(sfd, bind_ptr, bind_ptr_len);
	if (rv == -1)
	{
		cleanup(dst, sfd, handle, NULL, &src_info);
		return SOCKET_ERROR;
	}

	tcp_header_t tcp_hdr = {0};

	rv = pcap_handle_setup(&handle, src_info);
	if (rv != 0)
	{
		cleanup(dst, sfd, handle, NULL, &src_info);
		return rv;
	}

	rv = pcap_filter_setup(address, src_info);
	if (rv != 0)
	{
		cleanup(dst, sfd, handle, NULL, &src_info);
		return rv;
	}

	struct callback_data c_data = {0};

	if (dst->ai_family == AF_INET)
	{
		tcp_pseudo_ipv4_t tcp_pseudo_ipv4 = {0};
		create_ipv4_pseudo_hdr(&tcp_pseudo_ipv4, bind_ptr, dst, protocol);

		if (strncmp("127.0.0.1", address, 10) == 0)
		{
			c_data.loopback_flag = 1;
		}

		u_int8_t *checksum_buf = malloc(CHECKSUM_LEN_IPV4);
		if (checksum_buf == NULL)
		{
			cleanup(dst, sfd, handle, NULL, &src_info);
			return MEM_ALLOC_ERROR;
		}

		/* Start capture in a separate thread */
		pthread_t thread;
		rv = pthread_create(&thread, NULL, capture_thread, &c_data);
		if (rv != 0)
		{
			cleanup(dst, sfd, handle, checksum_buf, &src_info);
			return PTHREAD_CREATE;
		}

		rv = send_syn(sfd, dst, &tcp_hdr, &tcp_pseudo_ipv4, &c_data,
					  port_count, port_arr, src_info, checksum_buf,
					  dst->ai_family, thread);
		if (rv != 0)
		{
			cleanup(dst, sfd, handle, checksum_buf, &src_info);
			return rv;
		}

		/* Link capture to alarm */
		signal(SIGALRM, break_capture);

		/* Start capture timer */
		alarm(ALARM_SEC);

		/* Remove thread */
		void *thread_val;
		pthread_join(thread, &thread_val);
		if ((int)(intptr_t)thread_val != 0)
		{
			cleanup(dst, sfd, handle, checksum_buf, &src_info);
			return PCAP_LOOP;
		}

		/* Restore alarm handler */
		signal(SIGALRM, SIG_DFL);

		cleanup(dst, sfd, handle, checksum_buf, &src_info);
	}
	else if (dst->ai_family == AF_INET6)
	{
		tcp_pseudo_ipv6_t tcp_pseudo_ipv6 = {0};
		create_ipv6_pseudo_hdr(&tcp_pseudo_ipv6, bind_ptr, dst, protocol);

		if (strncmp("::1", address, 4) == 0)
		{
			c_data.loopback_flag = 1;
		}

		u_int8_t *checksum_buf = malloc(CHECKSUM_LEN_IPV6);
		if (checksum_buf == NULL)
		{
			cleanup(dst, sfd, handle, NULL, &src_info);
			return MEM_ALLOC_ERROR;
		}

		/* Start capture in a separate thread */
		pthread_t thread;
		rv = pthread_create(&thread, NULL, capture_thread, &c_data);
		if (rv != 0)
		{
			cleanup(dst, sfd, handle, checksum_buf, &src_info);
			return PTHREAD_CREATE;
		}

		rv = send_syn(sfd, dst, &tcp_hdr, &tcp_pseudo_ipv6, &c_data,
					  port_count, port_arr, src_info, checksum_buf,
					  dst->ai_family, thread);
		if (rv != 0)
		{
			cleanup(dst, sfd, handle, checksum_buf, &src_info);
			return rv;
		}

		/* Link capture to alarm */
		signal(SIGALRM, break_capture);

		/* Start capture timer */
		alarm(ALARM_SEC);

		/* Remove thread */
		void *thread_val;
		pthread_join(thread, &thread_val);
		if ((int)(intptr_t)thread_val != 0)
		{
			cleanup(dst, sfd, handle, checksum_buf, &src_info);
			return PCAP_LOOP;
		}

		/* Restore alarm handler */
		signal(SIGALRM, SIG_DFL);

		cleanup(dst, sfd, handle, checksum_buf, &src_info);
	}
	else
	{
		cleanup(dst, sfd, handle, NULL, &src_info);
		return UNKNOWN_FAMILY;
	}

	/* Only used during testing for formatting purposes */
	if (test_print)
	{
		int open_count = 0;
		printf("| PORT\tSTATE\n");

		for (int p_index = 0; p_index < port_count; p_index++)
		{
			if (c_data.port_status[port_arr[p_index]] == OPEN)
			{
				printf("│ %d\topen\n", port_arr[p_index]);
				open_count++;
			}
		}
		printf("│ %d ports are closed\n", port_count - open_count);
	}

	*is_open_port = c_data.any_open;

	/* Save results to supplied result_arr for use in caller */
	if (result_arr != NULL)
	{
		*result_arr = malloc(65536 * sizeof(unsigned short));
		if (*result_arr != NULL)
		{
			memcpy(*result_arr, (unsigned short *)c_data.port_status,
				   65536 * sizeof(unsigned short));
		}
	}

	return SUCCESS;
}
