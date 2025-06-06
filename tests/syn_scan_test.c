#include <stdio.h>
#include <stdlib.h>
#include "../include/syn_scan.h"
#include "../include/error.h"

void syn_scan_test(void)
{
	printf("-- SYN SCAN TESTS --\n");
	int ret;
	int count = 0;
	int *ports = NULL;
	if ((ports = parse_ports("1-65535", &count)) != NULL)
	{
		for (int i = 0; i < count; i++)
		{
			if (ports[i] != i + 1)
			{
				print_err("❌ Parse all ports failed", -1);
				return;
			}
		}
		printf("✅ Parse all ports test: Passed\n");
	}
	else
		print_err("❌ Parse all ports test failed", -1);

	if ((ports = parse_ports("1,,2-7,10-12,4444, 65535", &count)) != NULL)
	{
		int test_arr[12] = {1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 4444, 65535};
		for (int i = 0; i < count; i++)
		{
			if (ports[i] != test_arr[i])
			{
				print_err("❌ Parse mixed ports test failed", -1);
				return;
			}
		}
		printf("✅ Parse mixed ports test: Passed\n");
	}
	else
		print_err("❌ Parse mixed ports failed", -1);
	if ((ret = port_scan("192.168.1.228", ports, count)) == SUCCESS)
		printf("✅ IPv4 Port scan test: Passed\n");
	else
	{
		print_err("❌ IPv4 Port scan test failed", ret);
	}

	// TODO
	if ((ret = port_scan("some-ip", ports, count)) == SUCCESS)
		printf("✅ IPv6 Port scan test: Passed\n");
	else
		print_err("❌ IPv6 Port scan test failed", ret);

	free(ports);
}
