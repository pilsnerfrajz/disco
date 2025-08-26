#include <stdio.h>
#include <stdlib.h>

#include "../include/error.h"
#include "../include/cli.h"
#include "../include/arp.h"
#include "../include/ping.h"
#include "../include/syn_scan.h"

#define RETRIES 3

int default_scan(char *target)
{
	int rv = arp(target);
	if (rv == SUCCESS)
	{
		printf("Host %s is up!\n", target);
	}
	else
	{
		rv = ping(target, RETRIES);
		if (rv != SUCCESS)
		{
			print_err("ARP/ping", rv);
			return NO_RESPONSE;
		}
		printf("Host %s is up!\n", target);
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

	if (force_arp)
	{
		printf("Forcing ARP host discovery (skipping ICMP fallback)...\n");
		rv = arp(target);
		if (rv != SUCCESS)
		{
			print_err("ARP", rv);
			goto cleanup;
		}
		printf("Host %s is up!\n", target);
	}

	if (force_ping)
	{
		printf("Forcing ICMP host discovery (skipping ARP attempt)...\n");
		rv = ping(target, RETRIES);
		if (rv != SUCCESS)
		{
			print_err("Ping", rv);
			goto cleanup;
		}
		printf("Host %s is up!\n", target);
	}

	if (ports == NULL && no_host_disc && !force_arp && !force_ping)
	{
		fprintf(stderr, "WARNING: Doing nothing. Use '-p' with the '-n' option!\n\n");
		usage(stderr);
		rv = CLI_PARSE;
		goto cleanup;
	}

	if (no_host_disc)
	{
		printf("Skipping host status check...\n");
	}

	if (!no_host_disc && !force_arp && !force_ping)
	{
		rv = default_scan(target);
		if (rv != 0)
		{
			goto cleanup;
		}
	}

	if (ports != NULL)
	{
		int port_count = 0;
		unsigned short *port_arr = parse_ports(ports, &port_count);
		if (port_arr == NULL)
		{
			fprintf(stderr, "ERROR: an error occurred while parsing ports\n");
			rv = CLI_PARSE;
			goto cleanup;
		}
		rv = port_scan(target, port_arr, port_count, 1 /*Print state*/, NULL /*Return Array of Results*/);
		if (rv != SUCCESS)
		{
			print_err("TCP SYN", rv);
			free(port_arr);
			goto cleanup;
		}
		free(port_arr);
	}

cleanup:
	if (target != NULL)
	{
		free(target);
	}
	if (ports != NULL)
	{
		free(ports);
	}

	return rv;
}
