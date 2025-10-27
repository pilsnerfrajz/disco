#include <stdint.h>
#include <stdio.h>

#include "../include/fingerprint.h"

int determine_os(struct fingerprint *finger)
{
	if (finger->ttl == 0 && finger->window_size == 0)
	{
		return UNKNOWN_OS;
	}

	if (finger->ttl <= 64) /* Linux, mac or BSD*/
	{
		if (finger->mac[0] == 0x10 && finger->mac[1] == 0xbd && finger->mac[2] == 0x3a)
		{
			return MAC_OS;
		}
		if (finger->window_size == 65535)
		{
			return BSD_LIKE_OS;
		}
		else
		{
			return UNIX_LIKE_OS;
		}
	}
	else if (finger->ttl > 64 && finger->ttl <= 128)
	{
		return WINDOWS_OS;
	}
	else if (finger->ttl > 128)
	{
		return CISCO_OS;
	}
	else
	{
		return UNKNOWN_OS;
	}
}

int network_dist(int os, int ttl)
{
	int hops = 0;
	switch (os)
	{
	case UNIX_LIKE_OS:
		hops = 64 - ttl;
		break;
	case BSD_LIKE_OS:
		hops = 64 - ttl;
		break;
	case WINDOWS_OS:
		hops = 128 - ttl;
		break;
	case CISCO_OS:
		hops = 255 - ttl;
		break;
	case MAC_OS:
		hops = 64 - ttl;
		break;
	default:
		hops = -1;
	}
	return hops;
}
