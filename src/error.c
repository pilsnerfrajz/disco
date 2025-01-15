#include "../include/error.h"

#define ENUMS (sizeof(error_strings) / sizeof(error_strings[0]))

const char *const error_strings[] = {
	"Success",
	"No response from host",
	"Invalid or unknown host",
	"STRUCT_ERROR",
	"Error during socket operation",
	"Error during protocol lookup",
};

static_assert(ENUMS == COUNT, "Enums and err strings are not equal.\n");
