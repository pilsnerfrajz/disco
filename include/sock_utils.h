#ifndef SOCK_UTILS_H
#define SOCK_UTILS_H

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

#endif
