#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "../include/error.h"
#include "../include/syn_scan.h"
#include "../include/utils.h"

/**
 * @brief Prints the banner and usage information if -h or no arguments are given.
 *
 * @param stream Output stream (e.g., stdout or stderr).
 */
static void banner(FILE *stream)
{
	fprintf(stream,
			"@@@@@@@,   **  ,@@@@@@@  ,@@@@@@@  ,@@@@@@@,\n"
			"**     **  **  @@        **        **     **\n"
			"**     **  **  '@@@@@@,  **        **     **\n"
			"**     **  **        **  **        **     **\n"
			"@@@@@@@'   **  @@@@@@@'  '@@@@@@@  '@@@@@@@'\n\n"
			"disco - network utility for host discovery and port enumeration\n"
			"author: pilsnerfrajz\n\n");
	fprintf(stream,
			"usage: disco target [-h] [-p ports] [-o] [-n] [-P] [-a] [-S] [-w file]\n"
			"options:\n"
			"  target          : host to scan (IP address or domain)\n"
			"  -p, --ports     : ports to scan, e.g., -p 1-1024 or -p 21,22,80\n"
			"  -o, --open      : show open ports only (default: open or filtered)\n"
			"  -n, --no-check  : skip host status check\n"
			"  -P, --ping-only : force ICMP host discovery (skip ARP attempt)\n"
			"  -a, --arp-only  : force ARP host discovery  (skip ICMP fallback)\n"
			"  -S, --syn-only  : force SYN host discovery  (skip ARP and ICMP)\n"
			"  -w, --write     : write results to a file\n"
			"  -h, --help      : display this message\n");
}

void usage(FILE *stream)
{
	if (stream == stdout)
	{
		banner(stream);
	}
	else
	{
		fprintf(stream,
				"[!] usage: disco target [-h] [-p ports] [-o] [-n] [-P] [-a] [-S] [-w file]\n"
				"    options:\n"
				"      target          : host to scan (IP address or domain)\n"
				"      -p, --ports     : ports to scan, e.g., -p 1-1024 or -p 21,22,80\n"
				"      -o, --open      : show open ports only (default: open or filtered)\n"
				"      -n, --no-check  : skip host status check\n"
				"      -P, --ping-only : force ICMP host discovery (skip ARP attempt)\n"
				"      -a, --arp-only  : force ARP host discovery  (skip ICMP fallback)\n"
				"      -S, --syn-only  : force SYN host discovery  (skip ARP and ICMP)\n"
				"      -w, --write     : write results to a file\n"
				"      -h, --help      : display this message\n");
	}
}

int parse_cli(int argc, char *argv[], char **target, char **ports, int *show_open,
			  int *no_host_disc, int *force_ping, int *force_arp, int *force_syn,
			  char **write_file)
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
				"syn-only",
				no_argument,
				NULL,
				'S',
			},
			{
				"open",
				no_argument,
				NULL,
				'o',
			},
			{
				"write",
				required_argument,
				NULL,
				'w',
			},
			{0, 0, 0, 0}};

	int option;
	while ((option = getopt_long(argc, argv, "p:nhPaSow:", options, NULL)) != -1)
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
						fprintf(stderr, "[-] Invalid port specification: '-p %s'\n", optarg);
						usage(stderr);
						return CLI_PARSE;
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
		case 'w':
			if (optarg != NULL && write_file != NULL)
			{
				size_t len = strlen(optarg);
				if (len > 0)
				{
					*write_file = malloc(len + 1);
					if (*write_file)
					{
						strcpy(*write_file, optarg);
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
		case 'S':
			*force_syn = 1;
			break;
		case 'h':
			usage(stdout);
			return CLI_PARSE;
		case '?':
			if (optopt != 0)
			{
				if (optopt == 'p')
				{
					fprintf(stderr, "[-] Missing port(s) for '-p'\n");
				}
				else if (optopt == 'w')
				{
					fprintf(stderr, "[-] Missing file name for '-w'\n");
				}
				else
				{
					fprintf(stderr, "[-] Unknown option '-%c'\n", optopt);
				}
			}
			usage(stderr);
			return CLI_PARSE;
		default:
			fprintf(stderr, "[-] Unexpected argument: %c\n", option);
			usage(stderr);
			return CLI_PARSE;
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

	if (*force_arp + *force_ping + *force_syn + *no_host_disc > 1)
	{
		fprintf(stderr, "[-] Conflicting options. Only one of -P, -a, -S and -n can be used at once\n");
		usage(stderr);
		return CLI_PARSE;
	}

	if (*target == NULL)
	{
		fprintf(stderr, "[-] No valid target specified\n");
		usage(stderr);
		return CLI_PARSE;
	}

	return 0;
}
