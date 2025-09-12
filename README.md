

# 🪩 Disco
![Language](https://img.shields.io/badge/Language-C-%2300599C.svg)
[![Dependencies](https://img.shields.io/badge/Dependencies-libpcap-%230059.svg)](https://www.tcpdump.org/)
![OS](https://img.shields.io/badge/OS-Linux%2C%20macOS-ff8bba)
![Github actions](https://img.shields.io/badge/Github%20Actions-%23267.svg)
[![License](https://img.shields.io/badge/License-MIT-%2300.svg)](https://github.com/pilsnerfrajz/disco/blob/main/LICENSE)

Disco is a cross-platform network utility available on Linux and macOS. It supports multiple host discovery methods and offers robust status checks across various networks and configurations, together with fast and reliable port enumeration.

## Installation
1. Clone the repository
```bash
git clone https://github.com/pilsnerfrajz/disco.git
```
2. Navigate to the project directory
```bash
cd disco
```
3. Compile the program
```bash
make
```
4. Access and run the binary from the `bin` folder
```bash
sudo ./bin/disco
```

 In case there are issues when building the executable, `libpcap` may not be installed on your system. Follow the steps in the next section to install the required dependencies.

## Dependencies
Disco uses [libpcap](https://www.tcpdump.org/) to enable macOS users to send raw Ethernet frames and to filter received packets. To avoid having to write platform-dependent code, this library is required on Linux as well.

### Debian-based Systems
Update repositories and install `libpcap`
```bash
sudo apt update && sudo apt install -y libpcap-dev
```

### macOS
`libpcap` should come pre-installed on macOS. If it is not, it is available in Homebrew with
```bash
brew install libpcap
```

## Usage
> [!IMPORTANT]  
> Remember to enable IPv6 when using a VPN to allow scanning of IPv6 targets!
```
@@@@@@@,   **  ,@@@@@@@  ,@@@@@@@  ,@@@@@@@,
**     **  **  @@        **        **     **
**     **  **  '@@@@@@,  **        **     **
**     **  **        **  **        **     **
@@@@@@@'   **  @@@@@@@'  '@@@@@@@  '@@@@@@@'

disco - network utility for host discovery and port enumeration
author: pilsnerfrajz

usage: disco target [-h] [-p ports] [-o] [-n] [-P] [-a] [-S] [-w file]
options:
  target          : host to scan (IP address or domain)
  -p, --ports     : ports to scan, e.g., -p 1-1024 or -p 21,22,80
  -o, --open      : show open ports only (default: open or filtered)
  -n, --no-check  : skip host status check
  -P, --ping-only : force ICMP host discovery (skip ARP attempt)
  -a, --arp-only  : force ARP host discovery  (skip ICMP fallback)
  -S, --syn-only  : force SYN host discovery  (skip ARP and ICMP)
  -w, --write     : write results to a file
  -h, --help      : display this message
```

### Examples
```bash
# Simple scan
sudo ./bin/disco scanme.nmap.org -p 22,80,443

# Use ARP to check host status and write results to a file
sudo ./bin/disco 192.168.1.42 -a -w results.txt

# Check for open local ports. Skip host check since we know we are alive
sudo ./bin/disco 127.0.0.1 -n -p 1-65535
```

## Testing
The program includes comprehensive **integration tests** that validate real network functionality. Run with `make test` from the project root to test:
- ARP 
	- Requests to LAN devices 
	- Requests to external hosts
- Ping
	- IPv4/IPv6 localhost
	- Invalid domains and IP addresses
	- Valid Domains and IP addresses
- TCP SYN
	- Parsing of different port inputs
	- Port scan of IPv4/IPv6 localhost
	- Port scan of LAN device
	- Port scan of IPv4/IPv6 external hosts
- CLI
	- Setting all available CLI arguments
	- Printing of usage message with `-h` flag

Some tests may fail due to hardcoded IP addresses and port numbers not accessible or open on the targets in your network. Test cases that involve localhost or domains should still pass however. 

The future plan is to implement these tests in a CI pipeline using Docker to ensure working features, regardless of device and network configurations. 

## Technical Details

## License
