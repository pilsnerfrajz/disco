#ifndef HEADERS_H
#define HEADERS_H

#include <sys/types.h>
#include <arpa/inet.h>

/**
 * @brief Struct for easier setting of bits in the Data Offset and Reserved
 * fields of the TCP header.
 */
typedef struct tcp_offset_rsrvd
{
	u_int8_t offset : 4;
	u_int8_t rsrved : 4;
} tcp_offset_rsrvd_t;

/**
 * @brief Tcp header defined in RFC 9293.
 * https://www.rfc-editor.org/rfc/rfc9293#name-header-format
 */
typedef struct tcp_header
{
	u_int16_t sport;
	u_int16_t dport;
	u_int32_t seq;
	u_int32_t ack;
	tcp_offset_rsrvd_t offset_rsrvd;
	u_int8_t flags;
	u_int16_t window;
	u_int16_t checksum;
} tcp_header_t;

/**
 * @brief TCP IPv4 pseudo header according to RFC 9293.
 * https://www.ietf.org/rfc/rfc9293.html#v4pseudo
 *
 */
typedef struct tcp_pseudo_ipv4
{
	/* the IPv4 source address in network byte order */
	u_int32_t src_ip;
	/* the IPv4 destination address in network byte order */
	u_int32_t dst_ip;
	/* bits set to zero */
	u_int8_t zero;
	/* the protocol number from the IP header */
	u_int8_t ptcl;
	/* length of header + payload. Does not include the pseudo header */
	u_int16_t tcp_len;
} tcp_pseudo_ipv4_t;

/**
 * @brief TCP IPv6 pseudo header according to RFC 8200.
 * https://www.rfc-editor.org/rfc/rfc8200.html#section-8
 *
 */
typedef struct tcp_pseudo_ipv6
{
	struct in6_addr src_ip;
	struct in6_addr dst_ip;
	u_int32_t length;
	u_int32_t zero[3];
	u_int8_t next;
} tcp_pseudo_ipv6_t;

typedef struct ethernet_header
{
	/* Ethernet address of destination */
	u_int8_t dst[6];
	/* Ethernet address of sender */
	u_int8_t src[6];
	/* Protocol type */
	u_int16_t ptype;
} ethernet_header_t;

/**
 * @brief ARP packet according to RFC 826.
 */
typedef struct arp_packet
{
	/* Hardware address space (e.g., Ethernet) */
	u_int16_t hrd;
	/* Protocol address space */
	u_int16_t pro;
	/* Byte length of each hardware address */
	u_int8_t hln;
	/* Byte length of each protocol address */
	u_int8_t pln;
	/* Opcode REQUEST or REPLY */
	u_int16_t op;
	/* Hardware address of sender of this packet, hln bytes */
	u_int8_t sha[6];
	/* Protocol address of sender of this packet, pln bytes */
	u_int8_t spa[4];
	/* Hardware address of target of this packet (if known), hln bytes */
	u_int8_t tha[6];
	/* Protocol address of target (IP), pln bytes */
	u_int8_t tpa[4];
} arp_packet_t;

/**
 * @brief Combined Ethernet header and ARP packet.
 */
typedef struct arp_frame
{
	ethernet_header_t eth_hdr;
	arp_packet_t arp_pkt;
} arp_frame_t;

#endif
