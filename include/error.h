#ifndef ERROR_H
#define ERROR_H

#include <assert.h>

typedef enum err
{
	SUCCESS,
	NO_RESPONSE,
	UNKNOWN_HOST,
	STRUCT_ERROR,
	SOCKET_ERROR,
	PROTO_NOT_FOUND,
	COUNT, /* Not used, only for assert */
} err_t;

extern const char *const error_strings[];

#endif
