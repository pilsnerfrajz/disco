#include "../include/error.h"

#define ENUMS (sizeof(error_strings) / sizeof(error_strings[0]))

const char *const error_strings[] = {
	"Success",
	"No response from host",
	"Invalid or unknown host",
	"Error during socket operation",
	"Error during protocol lookup",
	"Error when allocating dynamic memory",
	"Error during interface lookup",
	"Buffers are not large enough",
	"Target or interface does not support ARP",
	"Host supports ARP",
	"pcap_init error",
	"pcap_open_live error",
	"pcap_inject error",
	"pcap_filter error",
	"pcap_loop error",
};

static_assert(ENUMS == COUNT, "Enums and err strings are not equal.\n");
