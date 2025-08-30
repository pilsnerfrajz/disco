#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "../include/syn_scan.h"
#include "../include/utils.h"

void banner(FILE *stream)
{
	fprintf(stream,
			"@@@@@@@,   **  ,@@@@@@@  ,@@@@@@@  ,@@@@@@@,\n"
			"**     **  **  @@        **        **     **\n"
			"**     **  **  '@@@@@@,  **        **     **\n"
			"**     **  **        **  **        **     **\n"
			"@@@@@@@'   **  @@@@@@@'  '@@@@@@@  '@@@@@@@'\n\n"
			"disco - network utility for host discovery and port enumeration\n"
			"author: pilsnerfrajz\n\n");
}

void usage(FILE *stream)
{
	if (stream == stdout)
	{
		banner(stream);
	}
	fprintf(stream,
			"usage: disco target [-h] [-p port(s)] [-n] [-P] [-a]\n"
			"options:\n"
			"  target          : host to scan (IP address or domain)\n"
			"  -p, --ports     : ports to scan, e.g., -p 1-1024 or -p 21,22,80\n"
			"  -o, --open      : show open ports only\n"
			"  -n, --no-check  : skip host status check\n"
			"  -P, --ping-only : force ICMP host discovery (skip ARP attempt)\n"
			"  -a, --arp-only  : force ARP host discovery (skip ICMP fallback)\n"
			"  -h, --help      : display this message\n");
}

int parse_cli(int argc, char *argv[], char **target, char **ports, int *show_open,
			  int *no_host_disc, int *force_ping, int *force_arp)
{
	/* Reset optind for multiple tests to work properly*/
	optind = 1;
	opterr = 0;

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
			{
				"open",
				no_argument,
				NULL,
				'o',
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
				if (len > 0)
				{
					int count = 0;
					unsigned short *temp_ports = parse_ports(optarg, &count);
					if (temp_ports == NULL)
					{
						fprintf(stderr, "[-] Invalid port specification: '-p %s'\n\n", optarg);
						usage(stderr);
						return -1;
					}
					free(temp_ports);
					/* Add one for null terminator */
					*ports = malloc(len + 1);
					if (*ports)
					{
						strcpy(*ports, optarg);
					}
				}
			}
			break;
		case 'o':
			*show_open = 1;
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
			usage(stdout);
			return -1;
		case '?':
			if (optopt != 0)
			{
				if (optopt == 'p')
				{
					fprintf(stderr, "[-] Missing port(s) for '-p'\n\n");
				}
				else
				{
					fprintf(stderr, "[-] Unknown option '-%c'\n\n", optopt);
				}
			}
			usage(stderr);
			return -1;
		default:
			fprintf(stderr, "[-] Unexpected argument: %c\n\n", option);
			usage(stderr);
			return -1;
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

	if (*force_arp + *force_ping + *no_host_disc > 1)
	{
		fprintf(stderr, "[-] Conflicting options. Only one of -P, -a and -n can be used at once\n\n");
		usage(stderr);
		return -1;
	}

	if (*target == NULL)
	{
		fprintf(stderr, "[-] No valid target specified\n\n");
		usage(stderr);
		return -1;
	}

	return 0;
}
