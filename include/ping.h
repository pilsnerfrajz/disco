#ifndef PING_H
#define PING_H

/**
 * @brief Pings an IPv4 or IPv6 address or domain.
 *
 * @param address The IPv4 or IPv6 address string or domain name to ping. Must
 * be a valid format, e.g., "93.184.215.14" or "example.com".
 * @param tries The number of echo requests to send.
 * @return `int` Returns `SUCCESS` if a reply is send and responded to
 * successfully. If no response is seen `NO_RESPONSE` is returned. If an error
 * occurs, one of the errors in `error.h` is returned.
 */
int ping(char *address, int tries);

#endif
