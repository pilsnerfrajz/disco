#include <stdio.h>
#include "../include/error.h"

#define ENUMS (sizeof(error_strings) / sizeof(error_strings[0]))

void print_err(char *function, int err_val)
{
	/* Don't care */
	if (err_val == -1)
	{
		fprintf(stderr, "%s\n", function);
		return;
	}
	fprintf(stderr, "%s: %s\n", function, error_strings[err_val]);
}

const char *const error_strings[] = {
	"Success",
	"No response from host",
	"Invalid or unknown host",
	"Permission denied, run with sudo",
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
	"Error creating thread",
	"An error occurred while getting source address",
	"Address family not supported",
	"Could not parse command line arguments"};

static_assert(ENUMS == COUNT, "Enums and err strings are not equal.\n");
