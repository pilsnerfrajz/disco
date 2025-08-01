#ifndef SYN_SCAN_H
#define SYN_SCAN_H

int port_scan(char *address, unsigned short *port_arr, int count, int print_state);
unsigned short *parse_ports(const char *port_str, int *port_count);

#endif
