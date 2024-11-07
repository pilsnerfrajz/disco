#ifndef PING_H
#define PING_H

/**
 * @brief Pings an IPv4 or IPv6 address.
 *
 * @param address The IPv4 or IPv6 address string to ping. Must be a valid
 * format, e.g., "93.184.215.14" or "2606:2800:21f:cb07:6820:80da:af6b:8b2c".
 * Hostnames or domain names are not valid arguments.
 * @param tries The number of echo requests to send.
 * @return `int` 0 if host is reachable within the number specified tries.
 * -1 if host is unreachable or if an error occurs (e.g., invalid address).
 */
int ping(char *address, int tries);

#endif