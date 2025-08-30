#include <stdio.h>
#include <stdlib.h>

#include "../include/error.h"
#include "../include/cli.h"
#include "../include/arp.h"
#include "../include/ping.h"
#include "../include/syn_scan.h"

#define RETRIES 3

static int default_scan(char *target)
{
	int rv = arp(target);
	if (rv == SUCCESS)
	{
		printf("[+] Host %s is up!\n", target);
	}
	else
	{
		printf("[!] ARP failed, falling back to ICMP\n");
		rv = ping(target, RETRIES);
		if (rv != SUCCESS)
		{
			print_err("[-] ping", rv);
			return NO_RESPONSE;
		}
		printf("[+] Host %s is up!\n", target);
	}

	return 0;
}

static void print_open_ports(unsigned short *res_arr,
							 unsigned short *port_arr,
							 int port_count,
							 int show_open)
{
	if (res_arr == NULL || port_arr == NULL)
	{
		fprintf(stderr, "[-] print_open_ports: An error occurred while printing open ports\n");
		return;
	}

	printf("\nPORT\tSTATE\n");

	int open_count = 0;
	int unknown_count = 0;
	for (int i = 0; i < port_count; i++)
	{
		unsigned short port = port_arr[i];
		if (res_arr[port] == OPEN)
		{
			printf("%d\topen\n", port);
			open_count++;
		}
		else if (res_arr[port] == UNKNOWN)
		{
			if (!show_open)
			{
				printf("%d\tunknown\n", port);
			}
			unknown_count++;
		}
	}

	if (open_count != port_count)
	{
		if (!show_open)
		{
			printf("\n[+] Found %d open port(s), %d unknown port(s), %d closed port(s) not shown\n",
				   open_count,
				   unknown_count,
				   port_count - open_count - unknown_count);
		}
		else
		{
			printf("\n[+] Found %d open port(s), %d unknown and %d closed port(s) not shown\n",
				   open_count,
				   unknown_count,
				   port_count - open_count - unknown_count);
		}
	}
	else if (open_count == port_count)
	{
		printf("\n[+] All scanned ports are open!\n");
	}
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

	unsigned short *port_arr = NULL;
	unsigned short *res_arr = NULL;

	int no_host_disc = 0;
	int force_ping = 0;
	int force_arp = 0;
	int show_open = 0;
	int rv = 0;

	if (parse_cli(argc, argv, &target, &ports, &show_open, &no_host_disc, &force_ping, &force_arp) != 0)
	{
		return CLI_PARSE;
	}

	if (force_arp)
	{
		printf("[!] Forcing ARP host discovery (skipping ICMP fallback)\n");
		rv = arp(target);
		if (rv != SUCCESS)
		{
			fprintf(stderr, "[-] ARP failed, try with '-P' instead\n\n");
			usage(stderr);
			goto cleanup;
		}
		printf("[+] Host %s is up!\n", target);
	}

	if (force_ping)
	{
		printf("[!] Forcing ICMP host discovery (skipping ARP attempt)\n");
		rv = ping(target, RETRIES);
		if (rv != SUCCESS)
		{
			print_err("[-] ping", rv);
			goto cleanup;
		}
		printf("[+] Host %s is up!\n", target);
	}

	if (ports == NULL && no_host_disc && !force_arp && !force_ping)
	{
		fprintf(stderr, "[!] Doing nothing. Use '-p' with the '-n' option!\n\n");
		usage(stderr);
		rv = CLI_PARSE;
		goto cleanup;
	}

	if (no_host_disc)
	{
		printf("[!] Skipping host status check\n");
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
		port_arr = parse_ports(ports, &port_count);
		if (port_arr == NULL)
		{
			fprintf(stderr, "[-] parse_ports: An error occurred while parsing ports\n");
			rv = CLI_PARSE;
			goto cleanup;
		}

		printf("[*] Scanning %d port(s) on %s...\n", port_count, target);
		short is_open_port = 0;

		rv = port_scan(target, port_arr, port_count, &is_open_port, &res_arr);
		if (rv != SUCCESS)
		{
			print_err("[-] port_scan", rv);
			goto cleanup;
		}

		printf("[+] Port scan results:\n");

		if (is_open_port)
		{
			print_open_ports(res_arr, port_arr, port_count, show_open);
		}
		else
		{
			printf("[!] No open port(s) found\n");
		}
	}

	// TODO Write results to file

cleanup:
	if (target != NULL)
	{
		free(target);
	}
	if (ports != NULL)
	{
		free(ports);
	}
	if (port_arr != NULL)
	{
		free(port_arr);
	}
	if (res_arr != NULL)
	{
		free(res_arr);
	}

	return rv;
}
