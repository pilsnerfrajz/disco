#include <stdio.h>
#include <stdlib.h>
#include "../include/syn_scan.h"
#include "../include/error.h"

#define TEST_ARR_LEN 14

void syn_scan_test(void)
{
	printf("-- SYN SCAN TESTS --\n");

	/* DEBUG: sudo lsof -PiTCP -sTCP:LISTEN */

	unsigned short parse_test_arr[10] = {1, 2, 3, 4, 5, 6, 10, 11, 4444, 65535};
	unsigned short test_arr[TEST_ARR_LEN] = {80, 4444, 5000, 6463, 7000, 10391,
											 17500, 17600, 17603, 44444, 59866,
											 61716, 64120, 65535};
	int ret;
	int all_port_count = 0;
	int test_port_count = 0;
	unsigned short *all_ports = NULL;
	unsigned short *parse_test_ports = NULL;
	char *lan_dev = "192.168.1.228";

	if ((all_ports = parse_ports("1-65535", &all_port_count)) != NULL)
	{
		for (int i = 0; i < all_port_count; i++)
		{
			if (all_ports[i] != i + 1)
			{
				print_err("❌ Parse all ports failed", -1);
				break;
			}
		}
		printf("✅ Parse all ports test: Passed\n");
	}
	else
	{
		print_err("❌ Parse all ports test failed", -1);
	}

	int parse_ok = 1;
	if ((parse_test_ports = parse_ports(
			 "-3333,0 ,1, ,2-    6,7a7b7c, 5,abc,10-11, 4444, 65535, 66666",
			 &test_port_count)) != NULL)
	{
		for (int i = 0; i < test_port_count; i++)
		{
			if (parse_test_arr[i] != parse_test_ports[i])
			{
				print_err("❌ Parse mixed ports test failed", -1);
				parse_ok = 0;
				break;
			}
		}
		if (parse_ok)
		{
			printf("✅ Parse mixed ports test: Passed\n");
		}
	}
	else
	{
		print_err("❌ Parse mixed ports failed", -1);
	}

	if ((ret = port_scan("127.0.0.1", test_arr, TEST_ARR_LEN, 1)) == SUCCESS)
		printf("✅ Localhost Port scan test: Passed\n");
	else
	{
		print_err("❌ Localhost Port scan test failed", ret);
	}

	if ((ret = port_scan("127.0.0.1", all_ports, all_port_count, 1)) == SUCCESS)
		printf("✅ Localhost all port scan test: Passed\n");
	else
	{
		print_err("❌ Localhost all port scan test failed", ret);
	}

	if ((ret = port_scan(lan_dev, test_arr, TEST_ARR_LEN, 1)) == SUCCESS)
		printf("✅ LAN device port scan test: Passed\n");
	else
	{
		print_err("❌ LAN device port scan test failed", ret);
	}

	if ((ret = port_scan(lan_dev, all_ports, all_port_count, 1)) == SUCCESS)
		printf("✅ LAN device all port scan test: Passed\n");
	else
	{
		print_err("❌ LAN device all port scan test failed", ret);
	}

	// TODO
	/*if ((ret = port_scan("some-ip", test_arr, count, 0)) == SUCCESS)
		printf("✅ IPv6 Port scan test: Passed\n");
	else
	{
		print_err("❌ IPv6 Port scan test failed", ret);
	}*/

	free(all_ports);
	free(parse_test_ports);
}
