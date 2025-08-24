#include <stdio.h>
#include "../include/cli.h"
#include "../include/error.h"

void cli_test(void)
{
	printf("-- CLI TESTS --\n");

	char *port_test[] = {"program", "-p", "80,443", NULL};

	parse_cli(3, port_test);
}
