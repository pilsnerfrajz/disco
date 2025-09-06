#include <stdio.h>
#include "../include/ping.h"
#include "../include/error.h"

void ping_test(void)
{
	printf("-- PING TESTS --\n");
	int ret;
	if ((ret = ping("256.1.1.1", 3)) == UNKNOWN_HOST)
		printf("✅ IPv4 invalid IP test: Passed\n");
	else
		print_err(stderr, "❌ IPv4 invalid IP test failed", ret);

	if ((ret = ping("2001:0db8::85a3::8a2e:0370:7334", 3)) == UNKNOWN_HOST)
		printf("✅ IPv6 invalid IP test: Passed\n");
	else
		print_err(stderr, "❌ IPv6 invalid IP test failed", ret);

	if ((ret = ping("127.0.0.1", 3)) == SUCCESS)
		printf("✅ IPv4 loopback ping test: Passed\n");
	else
		print_err(stderr, "❌ IPv4 loopback ping test failed", ret);

	if ((ret = ping("::1", 3)) == SUCCESS)
		printf("✅ IPv6 loopback ping test: Passed\n");
	else
		print_err(stderr, "❌ IPv6 loopback ping test failed", ret);

	if ((ret = ping("93.184.215.14", 3)) == SUCCESS)
		printf("✅ IPv4 IP of example.com ping test: Passed\n");
	else
		print_err(stderr, "❌ IPv4 IP of example.com ping test failed", ret);

	if ((ret = ping("2606:2800:21f:cb07:6820:80da:af6b:8b2c", 3)) == SUCCESS)
		printf("✅ IPv6 IP of example.com ping test: Passed\n");
	else
		print_err(stderr, "❌ IPv6 IP of example.com ping test failed", ret);

	if ((ret = ping("example.com", 3)) == SUCCESS)
		printf("✅ Valid domain name 'example.com' ping test: Passed\n");
	else
		print_err(stderr, "❌ Valid domain name 'example.com' ping test failed", ret);

	if ((ret = ping("example.xyz", 3)) == UNKNOWN_HOST)
		printf("✅ Invalid domain name 'example.xyz' ping test: Passed\n");
	else
		print_err(stderr, "❌ Invalid domain name 'example.xyz' ping test failed", ret);

	if ((ret = ping("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", 3)) == NO_RESPONSE)
		printf("✅ IPv6 unreachable address ping test: Passed\n");
	else
		print_err(stderr, "❌ IPv6 unreachable address ping test failed", ret);
}
