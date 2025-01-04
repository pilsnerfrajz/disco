#ifndef PING_H
#define PING_H

/**
 * @brief Pings an IPv4 or IPv6 address.
 *
 * @param address The IPv4 or IPv6 address string to ping. Must be a valid
 * format, e.g., "93.184.215.14" or "2606:2800:21f:cb07:6820:80da:af6b:8b2c".
 * Hostnames or domain names are not valid arguments.
 * @param tries The number of echo requests to send.
 * @return `int` Return code specifying the result of `ping`
 *
 * - 0: `PING_SUCCESS` if host is reachable within the number of specified tries.
 *
 * - 1: `NO_RESPONSE` if no response is seen within the number of specified tries.
 *
 * - 2: `INVALID_IP` if target IP address is invalid.
 *
 * - 3: `STRUCT_ERROR`if and errors occurs when setting up the necessary structs.
 *
 * - 4: `SOCKET_ERROR` if any socket error occurs.
 */
int ping(char *address, int tries);

#endif
