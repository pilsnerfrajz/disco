#ifndef SYN_SCAN_H
#define SYN_SCAN_H

int port_scan(char *address, unsigned short *port_arr, int count, int print_state);

/**
 * @brief Parses a string with a format similar to `"1,2,3-5,6"`, and returns it
 * as an unsigned short array `[1,2,3,4,5,6]`. The returned array should be freed with
 * `free()`.
 *
 * If ports numbers are below 1, they will be treated as 1. If they are above
 * 65535, they will be treated as 65535. Duplicate ports will be ignored.
 *
 * @param port_str The string to parse.
 * @param port_count int to store the number of ports in.
 * @return `unsigned short* array` with the parsed port numbers. NULL is
 * returned if an error occurs.
 */
unsigned short *parse_ports(const char *port_str, int *port_count);

#endif
