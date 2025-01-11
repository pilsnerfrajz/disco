#ifndef SOCK_UTILS_H
#define SOCK_UTILS_H

/**
 * @brief Gets a pointer to an addrinfo structure for the destination
 * IP address. Allows socket setup to be IP-address family agnostic.
 * The returned struct should be freed with `freeaddrinfo()`.
 *
 * @param dst IP string.
 * @param sock_type Socket type to be used in the `hints` struct, i.e `SOCK_RAW`.
 * @return `struct addrinfo*` on success. `NULL` if an error occurs.
 */
struct addrinfo *get_dst_addr_struct(char *, int);

/**
 * @brief Prints IPv4 addresses for debugging.
 * @param s `sockaddr_in *` struct.
 */
void print_ip(struct sockaddr_in *);

#endif
