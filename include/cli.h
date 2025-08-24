#ifndef CLI_H
#define CLI_H

void usage(FILE *stream);
int parse_cli(int argc,
			  char *argv[],
			  char **target,
			  char **ports,
			  int *no_host_disc,
			  int *force_ping,
			  int *force_arp);

#endif
