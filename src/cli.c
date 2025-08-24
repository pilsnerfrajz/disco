#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

void parse_cli(int argc, char *argv[])
{

	char *ports = NULL;

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

	printf("Ports: %s\n", ports);
}
