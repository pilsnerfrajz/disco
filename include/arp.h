#ifndef ARP_H
#define ARP_H

#include <sys/types.h>

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

#endif