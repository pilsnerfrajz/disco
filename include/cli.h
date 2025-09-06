#ifndef CLI_H
#define CLI_H

/**
 * @brief Print usage information.
 *
 * @param stream Output stream (e.g., stdout or stderr).
 */
void usage(FILE *stream);

/**
 * @brief Parse command line arguments.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param target Pointer to store the target IP address or domain.
 * @param ports Pointer to store the ports to scan.
 * @param show_open Flag to only show open ports.
 * @param no_host_disc Flag to skip host discovery.
 * @param force_ping Flag to force ICMP.
 * @param force_arp Flag to force ARP.
 * @param write_file Pointer to store the write_file path.
 * @return int 0 on success, CLI_PARSE on error.
 */
int parse_cli(int argc,
			  char *argv[],
			  char **target,
			  char **ports,
			  int *show_open,
			  int *no_host_disc,
			  int *force_ping,
			  int *force_arp,
			  char **write_file);

#endif
