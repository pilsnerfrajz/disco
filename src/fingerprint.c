#include <stdint.h>
#include <stdio.h>

#include "../include/fingerprint.h"

int determine_os(struct fingerprint *finger)
{
	// TODO Remove debug print
	printf("TTL: %d, Window Size: %d\n", finger->ttl, finger->window_size);

	if (finger->ttl == 0 && finger->window_size == 0)
	{
		return UNKNOWN_OS;
	}

	if (finger->ttl <= 64) /* Linux, mac or BSD*/
	{
		if (finger->window_size == 65535)
		{
			return BSD_LIKE_OS;
		}
		else
		{
			return LINUX_LIKE_OS;
		}
	}
	else if (finger->ttl > 64 && finger->ttl <= 128)
	{
		return WINDOWS_OS;
	}
	else if (finger->ttl > 128 && finger->ttl <= 255)
	{
		return CISCO_OS;
	}
	else
	{
		return UNKNOWN_OS;
	}
}
