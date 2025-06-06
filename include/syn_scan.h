#ifndef SYN_SCAN_H
#define SYN_SCAN_H

int port_scan(char *address, int *port_arr, int count);
int *parse_ports(const char *port_str, int *port_count);

#endif
