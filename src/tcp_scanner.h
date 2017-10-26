#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#include <map>
#include <mutex>
#include <vector>
#include "host.h"
#include "port_scanner.h"

using namespace std;

class TCPScanner : public PortScanner {
public:
    TCPScanner(map<string, shared_ptr<Host>> &_hosts, vector<int> &_ports, mutex* _hosts_mutex) :
        PortScanner(_hosts, _ports, _hosts_mutex) {}

private:
    unsigned char buffer[MAXPACKET];


    void prepare();
    void bind_sockets();
    void scan_host(shared_ptr<IPv4> host_ipv4);
    void recv_responses();
};

#endif
