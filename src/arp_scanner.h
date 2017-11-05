#ifndef ARPSCAN_H
#define ARPSCAN_H

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <iostream>
#include <memory>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/icmp6.h>    // struct icmp6_hdr and ICMP6_ECHO_REQUEST
// #include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netpacket/packet.h>
#include <set>
#include <map>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include "abstract_scanner.h"
#include "host.h"
#include "interface.h"

using namespace std;

/**
 * ARPScanner scans a local network by sending ARP requests
 * @param _interface Interface to use to perform the scan
 * @param _wait Time in ms to wait for responses. -1 means the default of 1s will be used
 */
class ARPScanner : public AbstractScanner {
public:
    ARPScanner(shared_ptr<Interface> _interface, int _wait);
    ARPScanner(string _interface, int _wait) : ARPScanner(make_shared<Interface>(_interface), _wait) {};

    void start();
    void stop();

private:
    /**
     * Interface to use to perform the scan
     */
    shared_ptr<Interface> interface;

    /**
     * Set of IP strings to which a request was sent
     */
    set<string> ips_scanned;

    /**
     * Buffer in which the general ARP packet is stored
     */
    unsigned char buffer[BUF_SIZE];

    /**
     * The socket address to send the request to
     * Contains information about the L2 layer
     */
    struct sockaddr_ll socket_address;

    void prepare();
    void bind_sockets();
    void recv_responses();
    void send_request(shared_ptr<IPv4> src, shared_ptr<IPv4> dst);
};

/**
 * structure used to prepare the ARP packet's header
 * @see https://en.wikipedia.org/wiki/Address_Resolution_Protocol
 */
struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

#endif
