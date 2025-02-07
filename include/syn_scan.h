#ifndef SYN_SCAN_H
#define SYN_SCAN_H

#include <sys/types.h>

/**
 * @brief Struct to set the TCP flags. Needs to be converted to a `u_int8_t`
 * when used in the TCP header.
 */
/*typedef struct tcp_flags
{
	u_int8_t cwr : 1;
	u_int8_t ece : 1;
	u_int8_t urg : 1;
	u_int8_t ack : 1;
	u_int8_t psh : 1;
	u_int8_t rst : 1;
	u_int8_t syn : 1;
	u_int8_t fin : 1;
} tcp_flags_t;*/

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

#endif
