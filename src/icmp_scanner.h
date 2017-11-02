#ifndef ICMP_SCANNER_H
#define ICMP_SCANNER_H

#include <memory>
#include "abstract_scanner.h"
#include "host.h"
#include "interface.h"
#include "ipv4.h"

using namespace std;

/**
 * Scan a (non)local subnet using ICMP echo requests
 * @param _ipv4 Subnet address with network IP and netmask
 * @param _if   Interface to use when scanning
 */
class ICMPScanner : public AbstractScanner {
public:
    ICMPScanner(shared_ptr<IPv4> _ipv4, shared_ptr<Interface> _if = nullptr);

    void start();
    void stop();

private:
    /**
     * IPv4 network address to scan
     */
    shared_ptr<IPv4> network;

    /**
     * Interface to use
     * If nullptr, no explicit binding is done
     */
    shared_ptr<Interface> interface;

    void prepare();
    void bind_sockets();
    void recv_responses();
    void send_request(shared_ptr<IPv4> _ipv4, int count);
};

#endif
