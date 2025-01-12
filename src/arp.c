#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>

#include <signal.h> /* Alarm to break pcap_loop */
#include <unistd.h> /* alarm() */

#ifdef __APPLE__
#include <net/if_dl.h>	  /* sockaddr_dl */
#include <net/if_types.h> /* IFT_ETHER */
#endif

#ifdef __linux__
#include <net/if_arp.h>		 /* ARPHRD_ETHER */
#include <linux/if_packet.h> /* AF_PACKET and sockaddr_ll */
#endif

/* Send/read packets */
#include <pcap/pcap.h>

#include "../include/arp.h"
#include "../include/sock_utils.h"

#define ETH_TYPE_IP4 0x0800
#define ETH_TYPE_ARP 0x0806
#define IF_NAME_SIZE 32		/* Should be large enough for interface names */
#define ETH_FRAME_SIZE 1518 /* https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II */
#define CAP_TIMEOUT 1000	/* Milliseconds */
#define ALARM_SEC 2

static pcap_t *handle;
struct callback_data
{
	struct arp_frame arp_frame;
	int reply_found;
};

/* Callback function for processing the received frames */
void process_pkt(u_char *user, const struct pcap_pkthdr *pkt_hdr,
				 const u_char *bytes)
{
	/* Captured packet is too small */
	if (pkt_hdr->caplen < sizeof(struct arp_frame))
	{
		return;
	}
	/* Cast user to original struct */
	struct callback_data *c_data = (struct callback_data *)user;

	struct arp_frame *reply = (struct arp_frame *)bytes;

	if (reply->eth_hdr.ptype == ntohs(ETH_TYPE_ARP) &&
		memcmp(reply->eth_hdr.dst, c_data->arp_frame.eth_hdr.src,
			   sizeof(reply->eth_hdr.dst)) == 0 &&
		memcmp(reply->arp_pkt.tpa, c_data->arp_frame.arp_pkt.spa,
			   sizeof(reply->arp_pkt.tpa)) == 0 &&
		memcmp(reply->arp_pkt.spa, c_data->arp_frame.arp_pkt.tpa,
			   sizeof(reply->arp_pkt.spa)) == 0)
	{
		c_data->reply_found = 1;
		pcap_breakloop(handle);
	}
	return;
}

void break_capture(int signum)
{
	(void)signum;
	pcap_breakloop(handle);
	return;
}

int arp(char *address)
{
	struct addrinfo *dst_info = get_dst_addr_struct(address, SOCK_DGRAM);
	if (dst_info == NULL)
	{
		freeaddrinfo(dst_info);
		return STRUCT_ERROR;
	}

	u_int8_t sender_ip[4];
	u_int8_t sender_mac[6];
	char *if_name = malloc(IF_NAME_SIZE);
	if (if_name == NULL)
	{
		freeaddrinfo(dst_info);
		return -1; // TODO
	}

	int ret = get_arp_details((struct sockaddr_in *)dst_info->ai_addr,
							  sender_ip, sender_mac, if_name, IF_NAME_SIZE);
	if (ret != SUCCESS)
	{
		freeaddrinfo(dst_info);
		free(if_name);
		return -1; // TODO
	}

	struct ethernet_header ethernet_header;
	struct arp_packet arp_packet;
	memset(&ethernet_header, 0, sizeof(ethernet_header));
	memset(&arp_packet, 0, sizeof(arp_packet));

	/* Populate Ethernet header
	 * https://en.wikipedia.org/wiki/EtherType
	 */
	memset(&ethernet_header.dst, 0xff, 6);
	memcpy(&ethernet_header.src, sender_mac, 6);
	ethernet_header.ptype = htons(ETH_TYPE_ARP);

	/* Populate ARP packet
	 * https://en.wikipedia.org/wiki/Address_Resolution_Protocol
	 */
	arp_packet.hrd = htons(1);
	arp_packet.pro = htons(ETH_TYPE_IP4);
	arp_packet.hln = 6;
	arp_packet.pln = 4;
	arp_packet.op = htons(1); /* Request */
	memcpy(&arp_packet.sha, sender_mac, sizeof(arp_packet.sha));
	memcpy(&arp_packet.spa, sender_ip, sizeof(arp_packet.spa));
	memcpy(&arp_packet.tpa,
		   &((struct sockaddr_in *)dst_info->ai_addr)->sin_addr.s_addr,
		   sizeof(arp_packet.tpa));
	/* arp_packet.tha already zero from memset on struct */

	/* Prepare frame */
	struct arp_frame arp_frame = {
		.eth_hdr = ethernet_header,
		.arp_pkt = arp_packet,
	};

	/* Initialize library */
	char errbuf[PCAP_ERRBUF_SIZE];
	int rv = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
	if (rv != 0)
	{
		fprintf(stderr, "Pcap_init error: %s\n", errbuf);
		free(if_name);
		return -1;
	}

	handle = pcap_open_live(if_name, ETH_FRAME_SIZE, 0, CAP_TIMEOUT,
							errbuf);
	if (handle == NULL)
	{
		freeaddrinfo(dst_info);
		free(if_name);
		fprintf(stderr, "Pcap_open_live error: %s\n", errbuf);
		return -1; // TODO
	}

	if (pcap_inject(handle, &arp_frame, sizeof(arp_frame)) < 0)
	{
		freeaddrinfo(dst_info);
		free(if_name);
		fprintf(stderr, "Pcap_inject error: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return -1; // TODO
	}

	/* Init to zeroes */
	struct bpf_program filter;
	char filter_expr[30];
	snprintf(filter_expr, sizeof(filter_expr),
			 "ether dst %02x:%02x:%02x:%02x:%02x:%02x",
			 sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3],
			 sender_mac[4], sender_mac[5]);

	rv = pcap_compile(handle, &filter, filter_expr, 0, 0);
	if (rv != 0)
	{
		freeaddrinfo(dst_info);
		free(if_name);
		fprintf(stderr, "Pcap_compile error: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return -1; // TODO
	}

	rv = pcap_setfilter(handle, &filter);
	if (rv != 0)
	{
		freeaddrinfo(dst_info);
		free(if_name);
		fprintf(stderr, "Pcap_compile error: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return -1; // TODO
	}

	/* Stop sniff if timeout */
	signal(SIGALRM, break_capture);

	/* Start capture timer */
	alarm(ALARM_SEC);

	/* Pass Ethernet header to check reply reversed in reply */
	struct callback_data c_data = {0};
	memcpy(&c_data.arp_frame, &arp_frame, sizeof(c_data.arp_frame));
	c_data.reply_found = 0;

	rv = pcap_loop(handle, 0, process_pkt, (u_char *)&c_data);
	if (rv == PCAP_ERROR)
	{
		freeaddrinfo(dst_info);
		free(if_name);
		fprintf(stderr, "Pcap_loop error: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return -1;
	}

	pcap_close(handle);
	freeaddrinfo(dst_info);
	free(if_name);

	if (c_data.reply_found)
	{
		return SUCCESS;
	}

	return -1; // TODO
}

int compare_subnets(in_addr_t src, in_addr_t dst, in_addr_t mask)
{
	int src_net = ntohl(src) & ntohl(mask);
	int dst_net = ntohl(dst) & ntohl(mask);

	if (src_net == dst_net)
	{
		return 0;
	}
	return -1; // TODO ??
}

int get_arp_details(struct sockaddr_in *dst, u_int8_t *src_ip,
					u_int8_t *src_mac, char *if_name, size_t if_size)
{
	struct ifaddrs *ifap;
	struct ifaddrs *ifa;
	int rv = getifaddrs(&ifap);
	if (rv != 0)
	{
		perror("getifaddrs");
		return STRUCT_ERROR;
	}

	/* Bools for checking if we have the wanted info */
	int net_mask = 0;
	int ip_addr = 0;
	int mac_addr = 0;

	char *iface = "";
	unsigned char *mac;
	struct sockaddr_in *ip;
	struct sockaddr_in *mask;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
	{
		/* Check if interface is loopback. Continue if it is */
		if (ip_addr && (((ntohl(ip->sin_addr.s_addr) & 0xFF000000) == 0x7F000000)))
		{
			net_mask = 0;
			ip_addr = 0;
			mac_addr = 0;
			continue;
		}

		if (ip_addr && mac_addr && net_mask)
		{
			/* If target and host are on the same subnet, ARP is possible */
			if (compare_subnets(ip->sin_addr.s_addr,
								dst->sin_addr.s_addr,
								mask->sin_addr.s_addr) != 0)
			{
				net_mask = 0;
				ip_addr = 0;
				mac_addr = 0;
				continue;
			}

			/* Buffers must be 4 and 6 bytes */
			if (sizeof(src_ip) >= 4 && sizeof(src_mac) >= 6)
			{
				memcpy(src_ip, &ip->sin_addr.s_addr, 4);
				memcpy(src_mac, mac, 6);
			}
			else
			{
				return -1; // TODO
			}

			/* Copy interface name to if_name */
			if (snprintf(if_name, if_size, "%s", iface) >= (int)if_size)
			{
				freeifaddrs(ifap);
				return -1; // TODO
			}

			freeifaddrs(ifap);
			return SUCCESS;
		}

		if (ifa->ifa_name != NULL)
		{
			/* If a new interface is found, reset */
			if (strcmp(iface, ifa->ifa_name) != 0)
			{
				iface = ifa->ifa_name;
				net_mask = 0;
				ip_addr = 0;
				mac_addr = 0;
			}
		}

/* AF_LINK = macOS */
#ifdef __APPLE__
		if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_LINK)
		{
			/* https://www.illumos.org/man/3SOCKET/sockaddr_dl */
			struct sockaddr_dl *s = (struct sockaddr_dl *)ifa->ifa_addr;

			if (s->sdl_type == IFT_ETHER)
			{
				/* Jump to address in sdl_data with macro */
				mac = (unsigned char *)LLADDR(s);
				mac_addr = 1;
			}
		}
#endif

/* UNTESTED */
#ifdef __linux__
		if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_PACKET)
		{
			/* https://www.illumos.org/man/3SOCKET/sockaddr_dl */
			struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;

			if (s->sll_hatype == ARPHRD_ETHER)
			{
				mac = (unsigned char *)s->sll_addr;
				mac_addr = 1;
			}
		}
#endif

		if (ifa->ifa_netmask != NULL && ifa->ifa_netmask->sa_family == AF_INET)
		{
			mask = (struct sockaddr_in *)(ifa->ifa_netmask);
			net_mask = 1;
		}

		if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET)
		{
			ip = (struct sockaddr_in *)ifa->ifa_addr;
			ip_addr = 1;
		}
	}

	freeifaddrs(ifap);
	return -1; // TODO
}
