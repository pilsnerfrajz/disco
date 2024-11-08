#include <stdio.h>
#include <stdlib.h>
#include "../include/ping.h"

// sample program. run with sudo
int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("Provide an IP as the first argument and the number of pings as the second\n");
		return -1;
	}

	printf("Pinging %s\n", argv[1]);
	int ret = ping(argv[1], atoi(argv[2]));
	switch (ret)
	{
	case 0:
		printf("Host is up!\n");
		break;
	case 1:
		printf("No response from host.\n");
		break;
	case 2:
		printf("Invalid IP address.\n");
		return -1;
		break;
	case 3:
		printf("Run program as sudo.\n");
		return -1;
		break;
	default:
		printf("Some error occurred.");
		return -1;
		break;
	}

	return 0;
}
