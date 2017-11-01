#ifndef UDP_SCANNER_H
#define UDP_SCANNER_H

#include <map>
#include <mutex>
#include <vector>
#include "host.h"
#include "port_scanner.h"

using namespace std;

class UDPScanner : public PortScanner {
public:
    UDPScanner(map<string, shared_ptr<Host>> &_hosts, vector<int> &_ports, mutex* _hosts_mutex, shared_ptr<Interface> _if = nullptr) :
        PortScanner(_hosts, _ports, _hosts_mutex, _if) {}

private:
    unsigned char buffer[MAXPACKET];


    void prepare();
    void bind_sockets();
    void scan_host(shared_ptr<Host>&, shared_ptr<IPv4>&);
    void recv_responses();
};

#endif
