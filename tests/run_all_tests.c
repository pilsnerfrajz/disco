#include <stdio.h>

extern void ping_test(void);

int main(void)
{
	printf("Running tests...\n");

	ping_test();

	return 0;
}
