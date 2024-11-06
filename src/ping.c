#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <errno.h>

#define TIMEOUT_SECONDS 2

typedef struct icmp6_pseudo_hdr
{
	struct in6_addr source;
	struct in6_addr dest;
	u_int32_t length;
	u_int32_t zero[3];
	u_int8_t next;
} icmp6_pseudo_hdr;

void exit_error(struct addrinfo *dst)
{
	if (dst != NULL)
		freeaddrinfo(dst);
	exit(EXIT_FAILURE);
}

int validate_ip(char *ip)
{
	struct in_addr ipv4_dst;
	struct in6_addr ipv6_dst;
	if (inet_pton(AF_INET, ip, &(ipv4_dst)) == 1 ||
		inet_pton(AF_INET6, ip, &(ipv6_dst)) == 1)
	{
		return 0;
	}
	return -1;
}

struct addrinfo *get_dst_addr_struct(char *dst)
{
	struct addrinfo *dst_info;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;
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
		freeaddrinfo(dst_info);
		return NULL;
	}

	return temp;
}

struct protoent *get_proto(struct addrinfo *dst_info)
{
	struct protoent *protocol;
	if (dst_info->ai_family == AF_INET)
	{
		protocol = getprotobyname("icmp");
	}
	else
	{
		protocol = getprotobyname("icmp6");
	}

	if (protocol == NULL)
	{
		return NULL;
	}

	return protocol;
}

int set_socket_options(int sfd)
{
	struct timeval timeout = {
		.tv_sec = TIMEOUT_SECONDS,
		.tv_usec = 0,
	};

	int rv = setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (rv == -1)
	{
		perror("Setsockopt");
		return -1;
	}

	return 0;
}

uint16_t calc_checksum(void *hdr, int len)
{
	uint16_t *temp = hdr;
	uint32_t sum = 0;

	/* count 16 bits each iteration */
	for (sum = 0; len > 1; len -= 2)
	{
		sum += *temp++;
	}

	if (len == 1)
	{
		sum += *(uint8_t *)temp;
	}

	while (sum >> 16)
	{
		sum = (sum >> 16) + (sum & 0xffff);
	}

	return ~sum;
}

struct icmp create_icmp4_echo_req_hdr(int seq)
{
	struct icmp req_hdr;
	memset(&req_hdr, 0, sizeof(req_hdr));
	req_hdr.icmp_type = ICMP_ECHO;
	req_hdr.icmp_code = 0;
	req_hdr.icmp_cksum = 0;
	req_hdr.icmp_hun.ih_idseq.icd_id = htons(getpid() & 0xffff);
	req_hdr.icmp_hun.ih_idseq.icd_seq = htons(seq);
	req_hdr.icmp_cksum = calc_checksum(&req_hdr, sizeof(req_hdr));

	return req_hdr;
}

struct icmp6_pseudo_hdr *create_icmp6_pseudo(int sfd, struct in6_addr dst)
{
	struct sockaddr_in6 src;
	socklen_t sock_len = sizeof(src);
	int rv = getsockname(sfd, (struct sockaddr *)&src, &sock_len);
	if (rv == -1)
	{
		return NULL;
	}

	icmp6_pseudo_hdr *pseudo_hdr = malloc(sizeof(icmp6_pseudo_hdr));
	if (pseudo_hdr == NULL)
	{
		return NULL;
	}

	pseudo_hdr->source = src.sin6_addr;
	pseudo_hdr->dest = dst;
	memset(pseudo_hdr->zero, 0, sizeof(pseudo_hdr->zero));
	pseudo_hdr->length = htonl(sizeof(struct icmp6_hdr)); // change struct?
	pseudo_hdr->next = IPPROTO_ICMPV6;

	return pseudo_hdr;
}

struct icmp6_hdr create_icmp6_echo_req_hdr(struct icmp6_pseudo_hdr pseudo_hdr, int seq)
{
	struct icmp6_hdr icmp6_hdr;
	memset(&icmp6_hdr, 0, sizeof(icmp6_hdr));
	icmp6_hdr.icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6_hdr.icmp6_code = 0;
	icmp6_hdr.icmp6_id = htons(getpid() & 0xffff);
	icmp6_hdr.icmp6_seq = htons(seq);
	icmp6_hdr.icmp6_cksum = calc_checksum(&pseudo_hdr, sizeof(pseudo_hdr) + sizeof(icmp6_hdr));

	return icmp6_hdr;
}

struct icmp *get_icmp4_reply_hdr(int sfd, struct addrinfo *dst)
{
	char recvbuf[sizeof(struct ip) + sizeof(struct icmp)];
	int recv_bytes = recv(sfd, &recvbuf, sizeof(recvbuf), 0);
	if (recv_bytes < 0)
	{
		if (errno == EWOULDBLOCK)
		{
			return NULL;
		}
		else
		{
			perror("Recv");
			exit_error(dst);
		}
	}
	if (recv_bytes == 0)
	{
		return NULL;
	}

	struct icmp *reply_hdr = (struct icmp *)(recvbuf + sizeof(struct ip));
	return reply_hdr;
}

int verify_icmp4_reply_hdr(struct icmp *reply_hdr, int seq)
{
	if (reply_hdr->icmp_type == ICMP_ECHOREPLY &&
		ntohs(reply_hdr->icmp_hun.ih_idseq.icd_seq) == seq &&
		ntohs(reply_hdr->icmp_hun.ih_idseq.icd_id) == (getpid() & 0xffff))
	{
		return 0;
	}
	return -1;
}

struct icmp6_hdr *get_icmp6_reply_hdr(int sfd, struct addrinfo *dst)
{
	char recvbuf[sizeof(struct icmp6_hdr)];
	int recv_bytes = recv(sfd, &recvbuf, sizeof(recvbuf), 0);
	if (recv_bytes < 0)
	{
		if (errno == EWOULDBLOCK)
		{
			return NULL;
		}
		else
		{
			perror("Recv");
			exit_error(dst);
		}
	}
	if (recv_bytes == 0)
	{
		return NULL;
	}

	struct icmp6_hdr *reply_hdr = (struct icmp6_hdr *)(recvbuf);
	return reply_hdr;
}

int verify_icmp6_reply_hdr(struct icmp6_hdr *reply_hdr, int seq)
{
	if (reply_hdr->icmp6_type == ICMP6_ECHO_REPLY &&
		ntohs(reply_hdr->icmp6_seq) == seq &&
		ntohs(reply_hdr->icmp6_id) == (getpid() & 0xffff))
	{
		return 0;
	}
	return -1;
}

int ping(char *dst, int count)
{
	int rv = validate_ip(dst);
	if (rv == -1)
	{
		fprintf(stderr, "Invalid IP address.\n");
		exit(EXIT_FAILURE);
	}

	struct addrinfo *dst_info = get_dst_addr_struct(dst);
	if (dst_info == NULL)
	{
		fprintf(stderr, "Failed getting target address info.\n");
		exit_error(dst_info);
	}

	struct protoent *protocol = get_proto(dst_info);
	if (protocol == NULL)
	{
		fprintf(stderr, "Could not find a protocol with the given name.\n");
		exit(EXIT_FAILURE);
	}

	int sfd = socket(dst_info->ai_family, SOCK_RAW, protocol->p_proto);
	if (sfd == -1)
	{
		perror("Socket");
		exit_error(dst_info);
	}

	rv = set_socket_options(sfd);
	if (rv == -1)
	{
		exit_error(dst_info);
	}

	rv = connect(sfd, dst_info->ai_addr, dst_info->ai_addrlen);
	if (rv < 0)
	{
		perror("Connect");
		exit_error(dst_info);
	}

	int seq = 0;
	int sent_bytes;
	int host_is_up = 0;
	if (dst_info->ai_family == AF_INET)
	{
		for (int attempt = 0; attempt < count; attempt++)
		{
			struct icmp icmp4_req_hdr = create_icmp4_echo_req_hdr(++seq);

			sent_bytes = send(sfd, &icmp4_req_hdr, sizeof(icmp4_req_hdr), 0);
			if (sent_bytes == -1)
			{
				continue;
			}

			struct icmp *reply_hdr = get_icmp4_reply_hdr(sfd, dst_info);
			if (reply_hdr == NULL)
			{
				continue;
			}

			rv = verify_icmp4_reply_hdr(reply_hdr, seq);
			if (rv == 0)
			{
				host_is_up = 1;
				break;
			}
		}
	}
	else
	{
		for (int attempt = 0; attempt < count; attempt++)
		{
			struct icmp6_hdr icmp6_hdr, *recv6_hdr;
			char recvbuf_ipv6[sizeof(struct icmp6_hdr)];

			memset(&icmp6_hdr, 0, sizeof(icmp6_hdr));
			icmp6_hdr.icmp6_type = ICMP6_ECHO_REQUEST;
			icmp6_hdr.icmp6_code = 0;
			icmp6_hdr.icmp6_id = htons(getpid() & 0xffff);
			icmp6_hdr.icmp6_seq = htons(++seq);
			icmp6_hdr.icmp6_cksum = 0;

			struct sockaddr_in6 src;
			socklen_t sock_len = sizeof(src);
			rv = getsockname(sfd, (struct sockaddr *)&src, &sock_len);
			if (rv == -1)
			{
				perror("Getsockname");
				exit_error(dst_info);
			}

			struct sockaddr_in6 *temp_sockaddr = (struct sockaddr_in6 *)dst_info->ai_addr;
			struct in6_addr dest_addr = temp_sockaddr->sin6_addr;
			icmp6_pseudo_hdr pseudo_hdr = {
				.source = src.sin6_addr,
				.dest = dest_addr,
				.zero = {0, 0, 0},
				.length = htonl(sizeof(icmp6_hdr)),
				.next = IPPROTO_ICMPV6,
			};

			icmp6_hdr.icmp6_cksum = calc_checksum(&pseudo_hdr, sizeof(pseudo_hdr) + sizeof(icmp6_hdr));

			int sent_bytes = send(sfd, &icmp6_hdr, sizeof(icmp6_hdr), 0);
			if (sent_bytes == -1)
			{
				perror("Send");
				exit_error(dst_info);
			}

			int recv_bytes = recv(sfd, &recvbuf_ipv6, sizeof(recvbuf_ipv6), 0);
			if (recv_bytes < 0)
			{
				if (errno == EWOULDBLOCK)
				{
					continue;
				}
				else
				{
					perror("Recv");
					exit_error(dst_info);
				}
			}

			recv6_hdr = (struct icmp6_hdr *)(recvbuf_ipv6);
			if (recv6_hdr->icmp6_type == ICMP6_ECHO_REPLY &&
				ntohs(recv6_hdr->icmp6_seq) == seq &&
				ntohs(recv6_hdr->icmp6_id) == (getpid() & 0xffff))
			{
				host_is_up = 1;
				break;
			}
			/*struct sockaddr_in6 *temp_sockaddr = (struct sockaddr_in6 *)dst_info->ai_addr;
			struct in6_addr dest_addr = temp_sockaddr->sin6_addr;
			struct icmp6_pseudo_hdr *pseudo_hdr = create_icmp6_pseudo(sfd, dest_addr);
			if (pseudo_hdr == NULL)
			{
				perror("Getsockname");
				exit_error(dst_info);
			}

			struct icmp6_hdr icmp6_hdr = create_icmp6_echo_req_hdr(*pseudo_hdr, ++seq);

			// icmp6_hdr.icmp6_cksum = calc_checksum(&pseudo_hdr, sizeof(*pseudo_hdr) + sizeof(icmp6_hdr));

			free(pseudo_hdr);

			sent_bytes = send(sfd, &icmp6_hdr, sizeof(icmp6_hdr), 0);
			if (sent_bytes == -1)
			{
				continue;
			}

			struct icmp6_hdr *reply_hdr = get_icmp6_reply_hdr(sfd, dst_info);
			if (reply_hdr == NULL)
			{
				continue;
			}

			rv = verify_icmp6_reply_hdr(reply_hdr, seq);
			if (rv == 0)
			{
				host_is_up = 1;
				break;
			}*/
		}
	}

	freeaddrinfo(dst_info);
	close(sfd);

	if (host_is_up)
		return 0;

	return -1;
}