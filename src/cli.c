#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "../include/utils.h"

void banner(void)
{
	printf("@@@@@@@,   **  ,@@@@@@@  ,@@@@@@@  ,@@@@@@@,\n"
		   "**     **  **  @@        **        **     **\n"
		   "**     **  **  '@@@@@@,  **        **     **\n"
		   "**     **  **        **  **        **     **\n"
		   "@@@@@@@'   **  @@@@@@@'  '@@@@@@@  '@@@@@@@'\n\n");
}

void usage(void)
{
	banner();
	printf("disco - network utility for host discovery and port enumeration\n"
		   "author: pilsnerfrajz\n\n"
		   "usage: disco target [-h] [-p port(s)] [-n] [-P] [-a]\n\n"
		   "options:\n"
		   "  target          : host to scan (IP address or domain)\n"
		   "  -p, --ports     : ports to scan, e.g., -p 1-1024 or -p 21,22,80\n"
		   "  -n, --no-check  : skip host discovery\n"
		   "  -P, --ping-only : force ICMP host discovery (skip ARP attempt)\n"
		   "  -a, --arp-only  : force ARP host discovery (skip ICMP fallback)\n"
		   "  -h, --help      : display this message\n\n");
}

void parse_cli(int argc, char *argv[], char **target, char **ports, int *no_host_disc, int *force_ping, int *force_arp)
{
	/* Reset optind for multiple tests to work properly*/
	optind = 1;

	static struct option options[] =
		{
			{
				"ports",
				required_argument,
				NULL,
				'p',
			},
			{
				"help",
				no_argument,
				NULL,
				'h',
			},
			{
				"no-check",
				no_argument,
				NULL,
				'n',
			},
			{
				"ping-only",
				no_argument,
				NULL,
				'P',
			},
			{
				"arp-only",
				no_argument,
				NULL,
				'a',
			},
			{0, 0, 0, 0}};

	int option;
	while ((option = getopt_long(argc, argv, "p:nhPa", options, NULL)) != -1)
	{
		switch (option)
		{
		case 'p':
			if (optarg != NULL && ports != NULL)
			{
				size_t len = strlen(optarg);
				/* Check if arg is at least one port */
				if (len > 1)
				{
					/* Add one for null terminator */
					*ports = malloc(len + 1);
					if (*ports)
					{
						strcpy(*ports, optarg);
					}
				}
			}
			break;
		case 'n':
			*no_host_disc = 1;
			break;
		case 'P':
			*force_ping = 1;
			break;
		case 'a':
			*force_arp = 1;
			break;
		case 'h':
			usage();
			return;
		default:
			// TODO invalid option print
			printf("Invalid option: %c\n", option);
			usage();
			return;
		}
	}

	/* Check unused options for valid domain or IP. First valid found is used */
	if (target != NULL)
	{
		while (optind < argc)
		{
			char *unused = argv[optind];
			struct addrinfo *r = get_dst_addr_struct(unused, SOCK_RAW);
			if (r != NULL)
			{
				if (target != NULL)
				{
					size_t len = strlen(unused);
					*target = malloc(len + 1);
					if (*target)
					{
						strcpy(*target, unused);
					}
				}
				free_dst_addr_struct(r);
				break;
			}
			optind++;
		}
	}

	// TODO print error if -P and -a are used at the same time
	/*
	printf("No host discovery: %s\n", no_host_disc ? "yes" : "no");
	printf("Use ping only: %s\n", use_ping ? "yes" : "no");
	printf("Use ARP only: %s\n", use_arp ? "yes" : "no");
	*/
}
