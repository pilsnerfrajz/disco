#include <stdio.h>

#include "include/arp_test.h"
#include "include/ping_test.h"

int main(void)
{
	ping_test();
	printf("\n");
	arp_test();

	return 0;
}
