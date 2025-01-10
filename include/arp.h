#ifndef ARP_H
#define ARP_H

#include <sys/types.h>
#include <netdb.h>

typedef enum err
{
	SUCCESS,
	STRUCT_ERROR,
	SOCKET_ERROR,
} err;

typedef struct ethernet_header
{
	/* Ethernet address of destination */
	u_int8_t dst[6];
	/* Ethernet address of sender */
	u_int8_t src[6];
	/* Protocol type */
	u_int16_t ptype;
} ethernet_header;

/**
 * @brief ARP packet according to RFC 826. Allocate memory for variable fields
 * dynamically.
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
	u_int8_t *sha;
	/* Protocol address of sender of this packet, pln bytes */
	u_int8_t *spa;
	/* Hardware address of target of this packet (if known), hln bytes */
	u_int8_t *tha;
	/* Protocol address of target (IP), pln bytes */
	u_int8_t *tpa;
} arp_packet;

/**
 * @brief Combined Ethernet header and ARP packet.
 */
typedef struct arp_frame
{
	ethernet_header eth_hdr;
	arp_packet arp_data;
} arp_frame;

int get_arp_details(struct sockaddr_in *, u_int8_t *, u_int8_t *);
int arp(char *);

#endif
