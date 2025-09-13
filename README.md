# 🪩 Disco
[![Language](https://img.shields.io/badge/Language-C-%2300599C.svg)](https://www.c-language.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-libpcap-%230059.svg)](https://www.tcpdump.org/)
![OS](https://img.shields.io/badge/OS-Linux%2C%20macOS-ff8bba)
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

 In case there are issues while building the executable, `libpcap` may not be installed on your system. Follow the steps in the next section to install the required dependencies.

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
**Simple scan**
```bash
sudo ./bin/disco scanme.nmap.org -p 22,80,443
```
**Use ARP to check host status and write results to a file**
```bash
sudo ./bin/disco 192.168.1.42 -a -w results.txt
```
**Check for open local ports and skip host check**
```bash
sudo ./bin/disco 127.0.0.1 -n -p 1-65535
```

## Folders

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
Disco is implemented in C using `libpcap` for frame injection and packet filtering. This section describes the implementation of ARP, ping and port scanning in more detail for those interested.

### Address Resolution Protocol (ARP)
Due to restrictions on raw layer 2 sockets in macOS, `libpcap` is used to inject Ethernet frames directly onto the network. ARP frames are manually crafted according to RFC 826 specifications and processed using the library's packet filtering capabilities. The protocol operates at the data link layer (Layer 2) of the OSI model, requiring platform-specific handling of include headers and definitions needed for interface processing of MAC addresses. This is successfully implemented to ensure reliable cross-platform functionality on both Linux and macOS.

ARP is the preferred method for local host discovery because it's fast, reliable, and operates below the network layer where firewalls typically filter traffic. Hosts are required to respond to ARP requests for proper network function. However, ARP is limited to the local network segment, which is why ICMP or SYN scanning, serves as the fallback for external hosts.

### ICMP Echo Request (Ping)
ICMP echo packets are manually crafted and sent to targets to check if they are reachable. This implementation supports both IPv4 and IPv6 hosts on loopback and external network interfaces. Received packets are processed to verify that they contain the correct ICMP reply type along with matching source and destination IP addresses. If no reply is received within two seconds, two additional requests are sent before timing out.

Ping supports DNS lookup and resolves domain names to IP addresses for usability. 

ICMP echo requests do not guarantee reliability since the protocol is connectionless, unlike TCP. It is also common for firewalls to block ICMP traffic, which can cause host discovery to fail. When ICMP fails to detect a host, disco falls back to TCP SYN scanning for host discovery. 

### TCP SYN 
A TCP SYN scan is used when both ARP and ping fail. The current implementation scans the target on port 22, 80 and 443 as they are commonly used. If any type of reply is sent back, the host is up. This principle is used for port scanning as well. Manual TCP segments are created with the SYN flag set, indicating that disco wants to start a conversation on the target port. If the target port is listening for connections, it will reply with a SYN-ACK flag. If it is not, a RST flag will be sent back. Below is an illustration of how the TCP 3-way handshake is used to determine if a port is open or closed.

**Open port**
```
Disco       SYN   ->  Target
Disco  <- SYN-ACK     Target
Disco       RST   ->  Target
Disco  <-   ACK       Target (Only with VPN)
```

**Closed port**
```
Disco       SYN   ->  Target
Disco  <-   RST       Target
```

After creating the proper header, it is sent to the target. With the use of multi-threading, packets can be sent in rapid succession to the next port, while listening for replies in a separate thread. This speeds up the scans significantly and allows for fast enumeration. The replies from the target are filtered with `libpcap`, similar to in the ARP implementation. It seems that normal socket operations are not always possible due to macOS restrictions. In this case, the macOS kernel appears to intercept raw TCP segments before they reach socket-related functions like `recv()`, but this is not an issue with `libpcap`. 

After capturing the replies, the packets are parsed manually and the TCP flags are inspected. If a SYN-ACK is received, the port is marked as open. When using a VPN, the SYN-ACKs are sometimes not captured, but instead an ACK reply after disco closes the connection with a RST flag. This seems to come from the VPN infrastructure and should never arrive unless the target port is open as seen in the illustration above. 

A total of three attempts will be made for each port, unless it has already been detected as open. Any port that does not send a reply back will be seen as filtered. This does not say anything about the state of the port and could be due to network issues or firewall blocking. 
