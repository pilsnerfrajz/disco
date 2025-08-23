#ifndef ARP_H
#define ARP_H

#include <sys/types.h>
#include <netdb.h>

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
