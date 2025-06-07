#include <stdio.h>
#include <stdlib.h>
#include "../include/syn_scan.h"
#include "../include/error.h"

void syn_scan_test(void)
{
	printf("-- SYN SCAN TESTS --\n");

	int test_arr[10] = {1, 2, 3, 4, 5, 6, 10, 11, 4444, 65535};
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
				break;
				;
			}
		}
		printf("✅ Parse all ports test: Passed\n");
	}
	else
	{
		print_err("❌ Parse all ports test failed", -1);
	}

	/* "Stress" test */
	if ((ports = parse_ports("-3333,0 ,1, ,2-    6,7a7b7c, 5,abc,10-11, 4444, 65535, 66666", &count)) != NULL)
	{
		for (int i = 0; i < count; i++)
		{
			if (ports[i] != test_arr[i])
			{
				print_err("❌ Parse mixed ports test failed", -1);
				break;
			}
		}
		printf("✅ Parse mixed ports test: Passed\n");
	}
	else
	{
		print_err("❌ Parse mixed ports failed", -1);
	}

	if ((ret = port_scan("192.168.1.1", test_arr, count, 1)) == SUCCESS)
		printf("✅ IPv4 Port scan test: Passed\n");
	else
	{
		print_err("❌ IPv4 Port scan test failed", ret);
	}

	// TODO
	if ((ret = port_scan("some-ip", test_arr, count, 0)) == SUCCESS)
		printf("✅ IPv6 Port scan test: Passed\n");
	else
	{
		print_err("❌ IPv6 Port scan test failed", ret);
	}

	free(ports);
}
