#include <stdio.h>
#include <stdlib.h>
#include "../include/syn_scan.h"
#include "../include/error.h"
#include "../include/ping.h"

#define TEST_ARR_LEN 14

void syn_scan_test(void)
{
	printf("-- SYN SCAN TESTS --\n");

	set_test_print_flag(1);

	/* DEBUG: sudo lsof -PiTCP -sTCP:LISTEN */

	unsigned short parse_test_arr[10] = {1, 2, 3, 4, 5, 6, 10, 11, 4444, 65535};
	unsigned short test_arr[TEST_ARR_LEN] = {80, 4444, 5000, 6463, 7000, 10391,
											 17500, 17600, 17603, 44444, 59866,
											 61716, 64120, 65535};
	unsigned short scanme_ports[] = {22, 80, 9929, 31337};
	int ret;
	int all_port_count = 0;
	int test_port_count = 0;
	unsigned short *all_ports = NULL;
	unsigned short *parse_test_ports = NULL;

	// TODO CHANGE DURING TESTING
	char *lan_dev = "192.168.x.x";

	if ((all_ports = parse_ports("1-65535", &all_port_count)) != NULL)
	{
		for (int i = 0; i < all_port_count; i++)
		{
			if (all_ports[i] != i + 1)
			{
				print_err(stderr, "❌ Parse all ports failed", -1);
				break;
			}
		}
		printf("✅ Parse all ports test: Passed\n");
	}
	else
	{
		print_err(stderr, "❌ Parse all ports test failed", -1);
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
				print_err(stderr, "❌ Parse mixed ports test failed", -1);
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
		print_err(stderr, "❌ Parse mixed ports failed", -1);
	}

	struct target_info target_info = {0};

	if ((ret = port_scan("127.0.0.1", test_arr, TEST_ARR_LEN, &target_info, NULL)) == SUCCESS)
		printf("└ ✅ Localhost IPv4 Port scan test: Passed\n");
	else
	{
		print_err(stderr, "└ ❌ Localhost IPv4 Port scan test failed", ret);
	}

	if ((ret = port_scan("::1", test_arr, TEST_ARR_LEN, &target_info, NULL)) == SUCCESS)
		printf("└ ✅ Localhost IPv6 Port scan test: Passed\n");
	else
	{
		print_err(stderr, "└ ❌ Localhost IPv6 Port scan test failed", ret);
	}

	/*if ((ret = port_scan("127.0.0.1", all_ports, all_port_count, &is_open, NULL)) == SUCCESS)
		printf("└ ✅ IPv4 Localhost full port scan test: Passed\n");
	else
	{
		print_err(stderr, "└ ❌ IPv4 Localhost full port scan test failed", ret);
	}

	if ((ret = port_scan("::1", all_ports, all_port_count, &is_open, NULL)) == SUCCESS)
		printf("└ ✅ IPv6 Localhost full port scan test: Passed\n");
	else
	{
		print_err(stderr, "└ ❌ IPv6 Localhost full port scan test failed", ret);
	}*/

	if (ping(lan_dev, 3) == SUCCESS)
	{
		if ((ret = port_scan(lan_dev, test_arr, TEST_ARR_LEN, &target_info, NULL)) == SUCCESS)
			printf("└ ✅ IPv4 LAN device port scan test: Passed\n");
		else
		{
			print_err(stderr, "└ ❌ IPv4 LAN device port scan test failed", ret);
		}

		/*if ((ret = port_scan(lan_dev, all_ports, all_port_count, &is_open, NULL)) == SUCCESS)
			printf("└ ✅ IPv4 LAN device full port scan test: Passed\n");
		else
		{
			print_err(stderr, "└ ❌ IPv4 LAN device full port scan test failed", ret);
		}*/
	}
	else
	{
		printf("❌ Cannot reach LAN device. Change lan_dev variable address in tests/syn_scan_test.c to run tests!\n");
	}

	// TODO
	/*if ((ret = port_scan("Lan-device-ip", test_arr, TEST_ARR_LEN, 1, NULL)) == SUCCESS)
		printf("✅ IPv6 Lan Port scan test: Passed\n");
	else
	{
		print_err(stderr, "❌ IPv6 Lan Port scan test failed", ret);
	}*/

	if ((ret = port_scan("scanme.nmap.org", scanme_ports, 4, &target_info, NULL)) == SUCCESS)
		printf("└ ✅ External IPv4 Port scan test: Passed\n");
	else
	{
		print_err(stderr, "└ ❌ External IPv4 Port scan test failed", ret);
	}

	if ((ret = port_scan("2600:3c01::f03c:91ff:fe18:bb2f", scanme_ports, 4, &target_info, NULL)) == SUCCESS)
		printf("└ ✅ External IPv6 Port scan test: Passed\n");
	else
	{
		print_err(stderr, "└ ❌ External IPv6 Port scan test failed", ret);
	}

	if (target_info.ttl <= 64)
	{
		printf("└ ✅ scanme.nmap.org TTL/Hop Limit test: Passed (Likely Linux: %d)\n", target_info.ttl);
	}
	else
	{
		printf("❌ scanme.nmap.org TTL/Hop Limit test: Failed (Value: %d)\n", target_info.ttl);
	}

	free(all_ports);
	free(parse_test_ports);
}
