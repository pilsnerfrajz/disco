#include <stdio.h>
#include "../include/ping.h"

void ping_test(void)
{
	printf("PING TESTS\n");
	int ret;
	if ((ret = ping("256.1.1.1", 3)) == 2)
		printf("✅ IPv4 invalid IP test passed\n");
	else
		printf("❌ IPv4 invalid IP test failed\n");

	if ((ret = ping("2001:0db8::85a3::8a2e:0370:7334", 3)) == 2)
		printf("✅ IPv6 invalid IP test passed\n");
	else
		printf("❌ IPv6 invalid IP test failed\n");

	if ((ret = ping("127.0.0.1", 3)) == 0)
		printf("✅ IPv4 loopback ping test passed\n");
	else
		printf("❌ IPv4 loopback ping test failed. Return code: %d\n", ret);

	if ((ret = ping("::1", 3)) == 0)
		printf("✅ IPv6 loopback ping test passed\n");
	else
		printf("❌ IPv6 loopback ping test failed\n");

	if ((ret = ping("93.184.215.14", 3)) == 0)
		printf("✅ IPv4 example.com ping test passed\n");
	else
		printf("❌ IPv4 example.com ping test failed. Return code: %d\n", ret);

	if ((ret = ping("2606:2800:21f:cb07:6820:80da:af6b:8b2c", 3)) == 0)
		printf("✅ IPv6 example.com ping test passed\n");
	else
		printf("❌ IPv6 example.com ping test failed. Return code: %d\n", ret);

	if ((ret = ping("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", 3)) == 1)
		printf("✅ IPv6 unreachable address ping test passed\n");
	else
		printf("❌ IPv6 unreachable address ping test failed. Return code: %d\n", ret);
}
