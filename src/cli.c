#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "../include/utils.h"

void parse_cli(int argc, char *argv[])
{

	char *ports = NULL;
	char *target = NULL;

	static struct option options[] =
		{
			{
				"ports",
				required_argument,
				NULL,
				'p',
			},
			{0, 0, 0, 0}};

	switch (getopt_long(argc, argv, "p:", options, NULL))
	{
	case 'p':
		ports = optarg;
		break;
	default:
		// usage
		break;
	}

	/* Check unused options for valid domain or IP. First valid found is used */
	if (!target)
	{
		while (optind < argc)
		{
			char *unused = argv[optind];
			struct addrinfo *r = get_dst_addr_struct(unused, SOCK_RAW);
			if (r != NULL)
			{
				target = unused;
				free_dst_addr_struct(r);
				break;
			}
			optind++;
		}
	}

	printf("Ports: %s\n", ports ? ports : "none");
	printf("Target: %s\n", target ? target : "none");
}
