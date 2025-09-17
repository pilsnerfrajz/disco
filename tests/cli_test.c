#include <stdio.h>
#include <stdlib.h>
#include "../include/cli.h"
#include "../include/error.h"

static void test(int number_of_flags, char *ports, int show_open, char *target, int no_host_disc, int force_ping, int force_arp)
{
	int set = 0;
	if (ports)
	{
		set++;
	}

	if (show_open)
	{
		set++;
	}

	if (target)
	{
		set++;
	}

	if (no_host_disc)
	{
		set++;
	}

	if (force_ping)
	{
		set++;
	}

	if (force_arp)
	{
		set++;
	}

	if (number_of_flags)
	{
		if (set == number_of_flags)
		{
			printf("✅ Set all options test: passed\n");
			return;
		}
		printf("❌ Set all options test: failed\n");
		return;
	}

	if (set == number_of_flags)
	{
		printf("✅ Usage flag test: passed\n");
		return;
	}
	printf("❌ Usage flag test: failed\n");
}

void cli_test(void)
{
	printf("-- CLI TESTS --\n");

	char *ports = NULL;
	char *target = NULL;
	char *file = NULL;
	int no_host_disc = 0;
	int force_ping = 0;
	int force_arp = 0;
	int force_syn = 0;
	int show_open = 0;

	char *help[] = {"program", "-h"};
	char *parse[] = {"program",
					 "-p",
					 "80,443",
					 "--no-check",
					 "-P",
					 "-o",
					 "-a",
					 "invalid",
					 "127.0.0.1",
					 "::1"};

	parse_cli(2, help, &target, &ports, &show_open, &no_host_disc, &force_ping, &force_arp, &force_syn, &file);

	test(0, ports, 0, target, no_host_disc, force_ping, force_arp);

	parse_cli(11, parse, &target, &ports, &show_open, &no_host_disc, &force_ping, &force_arp, &force_syn, &file);

	test(6, ports, 1, target, no_host_disc, force_ping, force_arp);

	free(ports);
	free(target);
}
