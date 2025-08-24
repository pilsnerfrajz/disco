#include <stdio.h>
#include "../include/cli.h"
#include "../include/error.h"

void cli_test(void)
{
	printf("-- CLI TESTS --\n");

	char *help[] = {"program", "-h", NULL};
	char *parse[] = {"program",
					 "-p",
					 "80,443",
					 "--no-check",
					 "-P",
					 "-a",
					 "invalid",
					 "127.0.0.1",
					 "::1", NULL};

	parse_cli(2, help);
	parse_cli(9, parse);
}
