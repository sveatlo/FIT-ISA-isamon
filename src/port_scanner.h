#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include "interface.h"
#include "host.h"
#include "abstract_scanner.h"

using namespace std;

/**
 * Abstract class to simplify using of different scanning techniques
 * @param _hosts       map of hosts to scan
 * @param _ports       vector of ports to scan, if empty ports 1-2^16 will be scanned
 * @param _hosts_mutex mutex to gain sole access to the hosts map
 * @param _if          interface to use during the scan, if nullptr, no explicit binding is done
 */
class PortScanner : public AbstractScanner {
public:
    PortScanner(map<string, shared_ptr<Host>> &_hosts, vector<int> &_ports, mutex* _hosts_mutex, shared_ptr<Interface> _if = nullptr);

    void start();
    void stop();

protected:
    /**
     * vector of ports to scan, if empty ports 1-2^16 will be scanned
     */
    vector<int> ports;

    /**
     * mutex to gain sole access to the hosts map
     */
    mutex* hosts_mutex;

    /**
     * interface to use during the scan, if nullptr, no explicit binding is done
     */
    shared_ptr<Interface> interface;

    /**
     * Buffer in which the general {TPC,UDP}/IP packet is stored
     */
    unsigned char buffer[MAXPACKET];

    /**
     * Start the scan of 1 hosts
     * @param host The host to scan
     * @param ipv4 The IPv4 address to use during this scan
     */
    virtual void scan_host(shared_ptr<Host>& host, shared_ptr<IPv4>& ipv4) =0;

    /**
     * Function used to receive responses. Runs in separate thread.
     */
    virtual void recv_responses() =0;
};

#endif
