#ifndef UTILS_H
#define UTILS_H

/**
 * @brief Gets a pointer to an addrinfo structure for the destination
 * IP address. Allows socket setup to be IP-address family agnostic.
 * The only fields available in the struct are `ai_addr`, `ai_addrlen`
 * and `ai_family`. The other fields are not initialized.
 * The returned struct should be freed with `free_dst_addr_struct`.
 *
 * @param dst IP string.
 * @param sock_type Socket type to be used in the `hints` struct, i.e `SOCK_RAW`.
 * @return `struct addrinfo*` on success. `NULL` if an error occurs.
 */
struct addrinfo *get_dst_addr_struct(char *, int);

/**
 * @brief Frees the struct returned by `get_dst_addr_struct()`.
 *
 * @param dst Struct returned by the `get_dst_addr_struct()`.
 */
void free_dst_addr_struct(struct addrinfo *);

/**
 * @brief Prints IPv4 addresses for debugging.
 * @param s `sockaddr_in *` struct.
 */
void print_ip(struct sockaddr_in *);

/**
 * @brief Validates IP address strings. Supports IPv4 and IPv6.
 *
 * @param ip The IP address to validate.
 * @return `int` 0 on valid address. -1 if the address is invalid
 * or if an error occurs.
 */
int validate_ip(char *);

/**
 * @brief Sets a timeout on the socket. The socket blocks for `s_timeout`
 * seconds if no data is received, before proceeding.
 *
 * @param sfd The socket file descriptor.
 * @return `int` 0 if options are set correctly. Otherwise -1.
 */
int set_socket_options(int sfd, int s_timeout);

#endif
