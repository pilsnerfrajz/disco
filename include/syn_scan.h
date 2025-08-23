#ifndef SYN_SCAN_H
#define SYN_SCAN_H

/**
 * @brief Performs a SYN scan on the specified ports of a target address or
 * domain. If `print_state` is true, the open ports will be printed. An array
 * containing the status of all scanned ports is available via the pointer
 * `result_arr`. `result_arr` should be freed with `free()`.
 *
 * Specifying a larger `count` than elements in `port_arr` will lead to
 * undefined behavior.
 *
 * @param address The target address to scan.
 * @param port_arr The array of ports to scan.
 * @param count The number of ports in the array.
 * @param print_state Whether to print the open ports.
 * @param result_arr Pointer to an array to store the results of the scan.
 * @return `int` Returns SUCCESS on success, or an error code from `error.h` on failure.
 */
int port_scan(char *address,
			  unsigned short *port_arr,
			  int count,
			  int print_state,
			  short **result_arr);

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
