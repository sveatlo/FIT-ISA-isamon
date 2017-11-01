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
    TCPScanner(map<string, shared_ptr<Host>> &_hosts, vector<int> &_ports, mutex* _hosts_mutex, shared_ptr<Interface> _if = nullptr) :
        PortScanner(_hosts, _ports, _hosts_mutex, _if) {}

private:
    unsigned char buffer[MAXPACKET];


    void prepare();
    void bind_sockets();
    void scan_host(shared_ptr<Host>&, shared_ptr<IPv4>&);
    void recv_responses();
};

#endif
