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

class ARPScanner : public AbstractScanner {
public:
    ARPScanner(shared_ptr<Interface>_interface);
    ARPScanner(string _interface) : ARPScanner(make_shared<Interface>(_interface)) {};

    void start();
    void stop();
    map<string, shared_ptr<Host>> get_hosts();

private:
    bool keep_scanning = true;
    int rcv_sd;
    int snd_sd;
    shared_ptr<Interface> interface;
    unsigned char buffer[BUF_SIZE];
    struct sockaddr_ll socket_address;

    void prepare();
    void bind_sockets();
    void recv_responses();
    void send_request(shared_ptr<IPv4> src, shared_ptr<IPv4> dst);
};

#endif
