#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#include <map>
#include <mutex>
#include <vector>
#include "host.h"
#include "port_scanner.h"

using namespace std;

/**
 * Performs TCP SYN scan on multiple hosts on multiple ports
 * @param _hosts       map of hosts to scan
 * @param _ports       vector of ports to scan, if empty ports 1-2^16 will be scanned
 * @param _hosts_mutex mutex to gain sole access to the hosts map
 * @param _wait Time to wait for responses. -1 means the default of 1s will be used
 * @param _if          interface to use during the scan, if nullptr, no explicit binding is done
 */
class TCPScanner : public PortScanner {
public:
    TCPScanner(map<string, shared_ptr<Host>> &_hosts, vector<int> &_ports, mutex* _hosts_mutex, int _wait, shared_ptr<Interface> _if = nullptr) :
        PortScanner(_hosts, _ports, _hosts_mutex, _wait, _if) {}

private:
    void prepare();
    void bind_sockets();
    void scan_host(shared_ptr<Host>&, shared_ptr<IPv4>&);
    void recv_responses();
};

#endif
