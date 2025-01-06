#ifndef ARP_H
#define ARP_H

#include <sys/types.h>

/* RFC 826 */
typedef struct arp_packet
{
	u_int16_t hrd; /* Hardware address space (e.g., Ethernet) */
	u_int16_t pro; /* Protocol address space */
	u_int8_t hln;  /* Byte length of each hardware address */
	u_int8_t pln;  /* Byte length of each protocol address */
	u_int16_t op;  /* Opcode REQUEST or REPLY */
	u_int8_t *sha; /* Hardware address of sender of this packet (MAC) */
	u_int8_t *spa; /* Protocol address of sender of this packet (IP) */
	u_int8_t *tha; /* Hardware address of target of this packet (if known) */
	u_int8_t *tpa; /* Protocol address of target (IP) */
} arp_packet;

#endif