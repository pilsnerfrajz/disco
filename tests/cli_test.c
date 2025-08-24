#include <stdio.h>
#include "../include/cli.h"
#include "../include/error.h"

void cli_test(void)
{
	printf("-- CLI TESTS --\n");

	char *parse[] = {"program", "-p", "80,443", "invalid", "127.0.0.1", "::1", NULL};

	parse_cli(6, parse);
}
