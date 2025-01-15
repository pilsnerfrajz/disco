#include <assert.h>

#define ENUMS (sizeof(error_strings) / sizeof(error_strings[0]))

/*#define PING_SUCCESS 0
#define NO_RESPONSE 1
#define INVALID_IP 2
#define STRUCT_ERROR 3
#define SOCKET_ERROR 4*/

typedef enum err
{
	SUCCESS,
	NO_RESPONSE,
	UNKNOWN_HOST,
	STRUCT_ERROR,
	SOCKET_ERROR,
	COUNT, /* Not used, only for assert */
} err_t;

static const char *const error_strings[] = {
	"Success",
	"No response from host",
	"Invalid or unknown host",
	"STRUCT_ERROR",
	"Error during socket operation",
};

static_assert(ENUMS == COUNT, "Enums and err strings are not equal.\n");
