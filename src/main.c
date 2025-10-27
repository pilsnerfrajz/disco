#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "../include/error.h"
#include "../include/cli.h"
#include "../include/arp.h"
#include "../include/ping.h"
#include "../include/syn_scan.h"
#include "../include/fingerprint.h"

#define RETRIES 3
#define MSG_BUF_SIZE 2048
#define DISCOVERY_PORT_COUNT 3
#define MAC_PRINT_BUF_SIZE (strlen("[+] MAC address: 00:xx:de:ad:be:ef") + 1)

static unsigned short discovery_ports[DISCOVERY_PORT_COUNT] = {22, 80, 443};

/**
 * @brief Print a message to a stream and to a file if provided.
 *
 * @param stream e.g. `stderr` or `stdout`
 * @param fp file pointer to an output file. Can be NULL.
 * @param msg message to print
 * @return int 0 on success, -1 if stream is NULL
 */
static int print_wrapper(FILE *stream, FILE *fp, const char *msg)
{
	if (stream == NULL)
	{
		return -1;
	}
	fprintf(stream, "%s", msg);
	if (fp != NULL)
	{
		fprintf(fp, "%s", msg);
	}
	return 0;
}

/**
 * @brief Default host discovery function. First tries ARP, then falls back to
 * ICMP if ARP fails.
 *
 * @param fp file pointer to an output file. Can be NULL.
 * @param target The target address to check.
 * @return `int` 0 on success, `NO_RESPONSE` if an error occurs.
 */
static int default_scan(FILE *fp, char *target, struct target_info *target_info)
{
	int rv = arp(target);
	if (rv == SUCCESS)
	{
		return 0;
	}

	char *msg = "[!] ARP failed, falling back to ICMP\n";
	print_wrapper(stdout, fp, msg);
	rv = ping(target, RETRIES);
	if (rv == SUCCESS)
	{
		return 0;
	}

	msg = "[!] Ping failed, falling back to TCP SYN\n";
	print_wrapper(stdout, fp, msg);

	target_info->is_open_port = 0;
	target_info->is_up = 0;
	rv = port_scan(target, discovery_ports, DISCOVERY_PORT_COUNT, target_info, NULL);
	if (rv != SUCCESS || !target_info->is_up)
	{
		msg = "[-] Host discovery failed. Host is down, aborting\n";
		print_wrapper(stderr, fp, msg);
		return NO_RESPONSE;
	}

	return 0;
}

/**
 * @brief Print open ports.
 *
 * @param res_arr Array of port scan results.
 * @param port_arr Array of ports supplied by the user.
 * @param port_count Number of ports in the user-supplied array.
 * @param show_open Flag to indicate whether to show only open ports.
 * @param fp File pointer to an output file. Can be NULL.
 */
static void print_open_ports(unsigned short *res_arr,
							 unsigned short *port_arr,
							 int port_count,
							 int show_open,
							 FILE *fp)
{
	char *m = NULL;
	char msg_buf[MSG_BUF_SIZE];
	if (res_arr == NULL || port_arr == NULL)
	{
		m = "[-] print_open_ports: An error occurred while printing open ports\n";
		print_wrapper(stderr, fp, m);
		return;
	}

	m = "\nPORT\tSTATE\n";
	print_wrapper(stdout, fp, m);

	int open_count = 0;
	int filtered_count = 0;
	for (int i = 0; i < port_count; i++)
	{
		unsigned short port = port_arr[i];
		if (res_arr[port] == OPEN)
		{
			snprintf(msg_buf, MSG_BUF_SIZE, "%d\topen\n", port);
			print_wrapper(stdout, fp, msg_buf);
			memset(msg_buf, 0, MSG_BUF_SIZE);
			open_count++;
		}
		else if (res_arr[port] == FILTERED)
		{
			if (!show_open)
			{
				snprintf(msg_buf, MSG_BUF_SIZE, "%d\tfiltered\n", port);
				print_wrapper(stdout, fp, msg_buf);
				memset(msg_buf, 0, MSG_BUF_SIZE);
			}
			filtered_count++;
		}
	}

	if (open_count != port_count)
	{
		if (!show_open)
		{
			snprintf(msg_buf, MSG_BUF_SIZE, "\n[+] Found %d open port(s), %d filtered port(s), %d closed port(s) not shown\n",
					 open_count,
					 filtered_count,
					 port_count - open_count - filtered_count);
			print_wrapper(stdout, fp, msg_buf);
			memset(msg_buf, 0, MSG_BUF_SIZE);
		}
		else
		{
			snprintf(msg_buf, MSG_BUF_SIZE, "\n[+] Found %d open port(s), %d filtered and %d closed port(s) not shown\n",
					 open_count,
					 filtered_count,
					 port_count - open_count - filtered_count);
			print_wrapper(stdout, fp, msg_buf);
			memset(msg_buf, 0, MSG_BUF_SIZE);
		}
	}
	else if (open_count == port_count)
	{
		m = "\n[+] All scanned ports are open!\n";
		print_wrapper(stdout, fp, m);
	}
}

static void print_os(int os, FILE *fp)
{
	char *msg = NULL;
	switch (os)
	{
	case UNIX_LIKE_OS:
		msg = "[+] Detected OS: Unix-like\n";
		break;
	case BSD_LIKE_OS:
		msg = "[+] Detected OS: BSD-like\n";
		break;
	case WINDOWS_OS:
		msg = "[+] Detected OS: Windows\n";
		break;
	case CISCO_OS:
		msg = "[+] Detected OS: Cisco\n";
		break;
	case MAC_OS:
		msg = "[+] Detected OS: macOS\n";
		break;
	default:
		msg = "[+] Detected OS: Unknown\n";
		break;
	}
	print_wrapper(stdout, fp, msg);
}

static int is_mac_empty(u_int8_t mac[6])
{
	static u_int8_t zero_mac[6] = {0};
	return memcmp(mac, zero_mac, 6) == 0;
}

static void print_mac(u_int8_t mac[6], FILE *fp)
{
	char m[MAC_PRINT_BUF_SIZE];
	snprintf(m, MAC_PRINT_BUF_SIZE, "[+] MAC address: %02x:%02x:%02x:%02x:%02x:%02x",
			 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	print_wrapper(stdout, fp, m);

	if (mac[0] == 0x10 && mac[1] == 0xbd && mac[2] == 0x3a)
	{
		char *vendor = " (Apple)";
		print_wrapper(stdout, fp, vendor);
	}

	print_wrapper(stdout, fp, "\n");
}

static void print_fingerprint(struct fingerprint finger,
							  struct target_info target_info,
							  FILE *fp,
							  char msg_buf[MSG_BUF_SIZE])
{
	finger.ttl = target_info.ttl;
	finger.window_size = target_info.window_size;
	memcpy(finger.mac, target_info.mac, 6);
	int os = determine_os(&finger);
	print_os(os, fp);
	if (target_info.is_open_port)
	{
		int hops = network_dist(os, finger.ttl);
		snprintf(msg_buf, MSG_BUF_SIZE, "[+] Network distance (estimate in hops): %d\n", hops);
		print_wrapper(stdout, fp, msg_buf);
		memset(msg_buf, 0, MSG_BUF_SIZE);
	}
	if (!is_mac_empty(target_info.mac))
	{
		print_mac(target_info.mac, fp);
	}
}

int main(int argc, char *argv[])
{
	if (argc == 1)
	{
		usage(stdout);
		return CLI_PARSE;
	}

	FILE *fp = NULL;

	char *ports = NULL;
	char *target = NULL;
	char *write_file = NULL;
	char *msg = NULL;
	char msg_buf[MSG_BUF_SIZE];

	unsigned short *port_arr = NULL;
	unsigned short *res_arr = NULL;

	int no_host_disc = 0;
	int force_ping = 0;
	int force_arp = 0;
	int force_syn = 0;
	int show_open = 0;
	int fingerprint_os = 0;
	int up = 0;
	int rv = 0;

	struct target_info target_info = {0};
	struct fingerprint finger = {0};

	if (parse_cli(argc, argv, &target, &ports, &show_open, &no_host_disc,
				  &force_ping, &force_arp, &force_syn, &fingerprint_os,
				  &write_file) != 0)
	{
		return CLI_PARSE;
	}

	if (getuid() != 0)
	{
		fprintf(stderr, "[-] Permission denied, run as root!\n");
		rv = PERMISSION_ERROR;
		goto cleanup;
	}

	if (write_file != NULL)
	{
		fp = fopen(write_file, "w");
		if (fp == NULL)
		{
			char *e = strerror(errno);
			fprintf(stderr, "[-] Failed to open '%s' for writing: %s\n", write_file, e);
			goto cleanup;
		}
		fprintf(fp, "[+] Command: ");
		for (int i = 0; i < argc; i++)
		{
			fprintf(fp, "%s ", argv[i]);
		}
		fprintf(fp, "\n");
	}

	if (force_arp)
	{
		msg = "[!] Forcing ARP host discovery (skipping ICMP fallback)\n";
		print_wrapper(stdout, fp, msg);
		rv = arp(target);
		if (rv != SUCCESS)
		{
			msg = "[-] ARP failed, try with '-P' instead\n";
			print_wrapper(stderr, fp, msg);
			goto cleanup;
		}
		up = 1;
	}

	if (force_ping)
	{
		msg = "[!] Forcing ICMP host discovery (skipping ARP attempt)\n";
		print_wrapper(stdout, fp, msg);
		rv = ping(target, RETRIES);
		if (rv != SUCCESS)
		{
			print_err(stderr, "[-] ping", rv);
			print_err(fp, "[-] ping", rv);
			goto cleanup;
		}
		up = 1;
	}

	if (force_syn)
	{
		msg = "[!] Forcing TCP SYN host discovery (skipping ARP and ICMP)\n";
		print_wrapper(stdout, fp, msg);
		target_info.is_open_port = 0;
		target_info.is_up = 0;
		rv = port_scan(target, discovery_ports, DISCOVERY_PORT_COUNT, &target_info, NULL);
		if (rv != SUCCESS || !target_info.is_up)
		{
			msg = "[-] TCP SYN host discovery failed\n";
			print_wrapper(stderr, fp, msg);
			rv = NO_RESPONSE;
			goto cleanup;
		}
		up = 1;
	}

	if (ports == NULL && no_host_disc && !force_arp && !force_ping && !force_syn)
	{
		msg = "[!] Doing nothing. Use '-p' with the '-n' option!\n\n";
		print_wrapper(stderr, fp, msg);
		usage(stderr);
		rv = CLI_PARSE;
		goto cleanup;
	}

	if (no_host_disc)
	{
		msg = "[!] Skipping host status check\n";
		print_wrapper(stdout, fp, msg);
	}

	if (!no_host_disc && !force_arp && !force_ping && !force_syn)
	{
		rv = default_scan(fp, target, &target_info);
		if (rv != 0)
		{
			goto cleanup;
		}
		up = 1;
	}

	if (up)
	{
		snprintf(msg_buf, MSG_BUF_SIZE, "[+] Host %s is up!\n", target);
		print_wrapper(stdout, fp, msg_buf);
		memset(msg_buf, 0, MSG_BUF_SIZE);
	}

	if (fingerprint_os && ports == NULL)
	{
		msg = "[!] Fingerprinting is more reliable when used with port scanning (-p)\n";
		print_wrapper(stdout, fp, msg);

		if (target_info.ttl == 0)
		{
			rv = port_scan(target, discovery_ports, DISCOVERY_PORT_COUNT, &target_info, NULL);
			if (rv != SUCCESS)
			{
				msg = "[-] Fingerprinting failed, aborting\n";
				print_wrapper(stderr, fp, msg);
				goto cleanup;
			}
		}
		if (target_info.is_up)
		{
			print_fingerprint(finger, target_info, fp, msg_buf);
		}
	}

	if (ports != NULL)
	{
		int port_count = 0;
		port_arr = parse_ports(ports, &port_count);
		if (port_arr == NULL)
		{
			msg = "[-] parse_ports: An error occurred while parsing ports\n";
			print_wrapper(stderr, fp, msg_buf);
			rv = CLI_PARSE;
			goto cleanup;
		}

		snprintf(msg_buf, MSG_BUF_SIZE, "[*] Scanning %d port(s) on %s...\n", port_count, target);
		print_wrapper(stdout, fp, msg_buf);
		memset(msg_buf, 0, MSG_BUF_SIZE);

		target_info.is_open_port = 0;
		target_info.is_up = 0;

		rv = port_scan(target, port_arr, port_count, &target_info, &res_arr);
		if (rv != SUCCESS)
		{
			print_err(stderr, "[-] port_scan", rv);
			goto cleanup;
		}

		if (target_info.is_open_port)
		{
			print_wrapper(stdout, fp, "[+] Port scan results:\n");
			print_open_ports(res_arr, port_arr, port_count, show_open, fp);
		}
		else
		{
			msg = "[!] No open port(s) found\n";
			print_wrapper(stdout, fp, msg);
		}

		if (target_info.is_up)
		{
			print_fingerprint(finger, target_info, fp, msg_buf);
		}
	}

	if (fp != NULL)
	{
		fprintf(stdout, "[+] Wrote results to file: %s\n", write_file);
	}

cleanup:
	if (target != NULL)
	{
		free(target);
	}
	if (ports != NULL)
	{
		free(ports);
	}
	if (port_arr != NULL)
	{
		free(port_arr);
	}
	if (res_arr != NULL)
	{
		free(res_arr);
	}
	if (write_file != NULL)
	{
		free(write_file);
	}
	if (fp != NULL)
	{
		fclose(fp);
	}

	return rv;
}
