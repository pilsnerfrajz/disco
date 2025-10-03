#include <stdio.h>
#include <string.h>

#include "../include/fingerprint.h"
#include "../include/syn_scan.h"
#include "../include/error.h"

#define TEST_ARR_LEN 3

void fingerprint_tests(void)
{
	int ret;
	struct target_info target_info = {0};
	struct fingerprint finger = {0};
	unsigned short test_arr[] = {22, 80, 8080};

	if ((ret = port_scan("192.168.1.228", test_arr, TEST_ARR_LEN, &target_info, NULL)) == SUCCESS)
	{
		finger.ttl = target_info.ttl;
		finger.window_size = target_info.window_size;
		if (determine_os(&finger) == LINUX_OS)
			printf("✅ Fingerprint of Linux host test: Passed\n");
		else
			fprintf(stderr, "❌ Fingerprint of Linux host test failed: Detected OS %d\n", determine_os(&finger));
	}
	else
	{
		print_err(stderr, "Port_scan", ret);
		fprintf(stderr, "❌ Fingerprint of Linux host test failed: Detected OS %d\n", determine_os(&finger));
	}

	memset(&finger, 0, sizeof(finger));
	memset(&target_info, 0, sizeof(target_info));

	if ((ret = port_scan("192.168.1.140", test_arr, TEST_ARR_LEN, &target_info, NULL)) == SUCCESS)
	{
		finger.ttl = target_info.ttl;
		finger.window_size = target_info.window_size;
		if (determine_os(&finger) == WINDOWS_OS)
			printf("✅ Fingerprint of Windows host test: Passed\n");
		else
			fprintf(stderr, "❌ Fingerprint of Windows host test failed: Detected OS %d\n", determine_os(&finger));
	}
	else
	{
		print_err(stderr, "Port_scan", ret);
		fprintf(stderr, "❌ Fingerprint of Windows host test failed: Detected OS %d\n", determine_os(&finger));
	}

	memset(&finger, 0, sizeof(finger));
	memset(&target_info, 0, sizeof(target_info));

	if ((ret = port_scan("192.168.1.206", test_arr, TEST_ARR_LEN, &target_info, NULL)) == SUCCESS)
	{
		finger.ttl = target_info.ttl;
		finger.window_size = target_info.window_size;
		if (determine_os(&finger) == MAC_BSD_OS)
			printf("✅ Fingerprint of mac host test: Passed\n");
		else
			fprintf(stderr, "❌ Fingerprint of mac host test failed: Detected OS %d\n", determine_os(&finger));
	}
	else
	{
		print_err(stderr, "Port_scan", ret);
		fprintf(stderr, "❌ Fingerprint of mac host test failed: Detected OS %d\n", determine_os(&finger));
	}

	memset(&finger, 0, sizeof(finger));
	memset(&target_info, 0, sizeof(target_info));

	if ((ret = port_scan("192.168.1.1", test_arr, TEST_ARR_LEN, &target_info, NULL)) == SUCCESS)
	{
		finger.ttl = target_info.ttl;
		finger.window_size = target_info.window_size;
		if (determine_os(&finger) == ROUTER_OS)
			printf("✅ Fingerprint of router host test: Passed\n");
		else
			fprintf(stderr, "❌ Fingerprint of router host test failed: Detected OS %d\n", determine_os(&finger));
	}
	else
	{
		print_err(stderr, "Port_scan", ret);
		fprintf(stderr, "❌ Fingerprint of router host test failed: Detected OS %d\n", determine_os(&finger));
	}
}
