#include <stdio.h>
#include <stdlib.h>
#include "../include/ping.h"

// sample program
int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("Provide an IP as the first argument and the number of pings as the second\n");
		return -1;
	}

	printf("Pinging %s\n", argv[1]);
	int ret = ping(argv[1], atoi(argv[2]));
	if (ret == 0)
	{
		printf("Host is up!\n");
	}
	else
	{
		printf("Host appears to be down or error occured\n");
		return -1;
	}

	return 0;
}
