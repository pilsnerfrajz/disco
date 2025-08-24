#include <stdio.h>
#include "../include/error.h"
#include "../include/cli.h"
#include "../include/arp.h"
#include "../include/ping.h"
#include "../include/syn_scan.h"

int default_scan(char *target, char *ports)
{
	int rv = arp(target);
	if (rv == SUCCESS)
	{
		printf("Host %s is up!\n", target);
	}
	else
	{
		rv = ping(target, 3);
		if (rv != SUCCESS)
		{
			print_err("ARP/ping", rv);
			return NO_RESPONSE;
		}
		printf("Host %s is up!\n", target);
	}

	if (ports != NULL)
	{
		int port_count = 0;
		unsigned short *port_arr = parse_ports(ports, &port_count);
		if (port_arr == NULL)
		{
			fprintf(stderr, "ERROR: an error occurred while parsing ports\n");
			return -1;
		}
		rv = port_scan(target, port_arr, port_count, 1 /*Print state*/, NULL /*Return Array of Results*/);
		if (rv != SUCCESS)
		{
			print_err("TCP SYN", rv);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc == 1)
	{
		usage(stdout);
		return CLI_PARSE;
	}
	char *ports = NULL;
	char *target = NULL;
	int no_host_disc = 0;
	int force_ping = 0;
	int force_arp = 0;
	int rv = 0;

	if (parse_cli(argc, argv, &target, &ports, &no_host_disc, &force_ping, &force_arp) != 0)
	{
		return CLI_PARSE;
	}

	rv = default_scan(target, ports);
	if (rv != 0)
	{
		return rv;
	}

	return 0;
}
