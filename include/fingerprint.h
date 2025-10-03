#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <sys/types.h>

struct fingerprint
{
	u_int8_t ttl;
	u_int16_t window_size;
};

int determine_os(struct fingerprint *finger);

#endif
