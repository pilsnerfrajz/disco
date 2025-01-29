#ifndef ARP_H
#define ARP_H

#include <sys/types.h>
#include <netdb.h>

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

/**
 * @brief Get the details needed for creating an ARP frame.
 *
 * @param dst `sockaddr_in *` structure containing address of the target.
 * @param src_ip_buf Buffer to store the IP address of the sender.
 * @param src_mac_buf Buffer to store the MAC address of the sender.
 * @param if_name `char *` to store the interface name in.
 * @param if_size The size of the allocated memory for `if_name`.
 * @return int Returns `ARP_SUPP` if the target is on the same subnet as the
 * sender. If they are not, `ARP_NOT_SUPP` is returned. If an error occurs, one
 * of the errors in `error.h` is returned.
 */
int get_arp_details(struct sockaddr_in *dst, u_int8_t *src_ip_buf,
					u_int8_t *src_mac_buf, char *if_name, size_t if_size);

/**
 * @brief Send an ARP request to `address` and processes the reply.
 *
 * @param address The target address.
 * @return int Returns `SUCCESS` if the request was sent successfully and the
 * target responds. Otherwise, it returns one of the errors in `error.h`.
 */
int arp(char *address);

#endif
