# ISAMon

## Project description
Simple TCP/UDP network scanner created as a project assignment of the ISA course.

## Author
written by Svätopluk Hanzel <xhanze10@stud.fit.vutbr.cz>

## Usage
isamon can scan local and non-local networks for live hosts and than perform a TCP/UDP port scan

### Parameters
Using:
 * -h will print help
 * -i <name> will use this interface in all scans
 * -t will perform a TCP scan on all live hosts
 * -u will perform a UDP scan on all live hosts
 * -p <port> will scan this port (can be used multiple times)
 * -n <subnet/netmask> will scan this network (can be combined with -i)
 * -w <time> will wait a max <time> ms before moving on. Default for ARP scan is 1s, for ICMP 2s, for TCP 1s, for UDP 1.1s per host

### Exit codes
On successfull exit, isamon returns 0 and no error message is written out.
In case isamon encounters an error, a non-zero error code is returned and an error message is written to stderr. Table of possible exit codes is below.

| code  | message/reason                        |
|-------|---------------------------------------|
| 1     | Invalid arguments                     |
| 101   | Interface error                       |
| 102   | Socket bind error                     |
| 103   | ARP scanning error                    |
| 104   | ARP receiving error                   |
| 105   | ICMP scanning error                   |
| 106   | ICMP receiving error                  |
| 107   | TCP scanning error                    |
| 108   | TCP receiving error                   |
| 109   | UDP scanning error                    |
| 110   | UDP receiving error                   |
| 150   | Cannot get MAC address for interface  |
| 254   | Run isamon as root, stupid!           |
| 255   | Excessive use of Ctrl+c               |
