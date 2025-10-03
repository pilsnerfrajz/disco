#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <sys/types.h>

#define UNKNOWN_OS 1
#define LINUX_LIKE_OS 2
#define BSD_LIKE_OS 3
#define WINDOWS_OS 4
#define CISCO_OS 5

#define LINUX_TTL 64
#define BSD_FAMILY_TTL 64
#define WINDOWS_TTL 128
#define CISCO_TTL 255

#define BSD_WIN_SIZE 65535

struct fingerprint
{
	u_int8_t ttl;
	u_int16_t window_size;
};

int determine_os(struct fingerprint *finger);

#endif
