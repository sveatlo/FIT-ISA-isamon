#ifndef ICMP_SCANNER_H
#define ICMP_SCANNER_H

#include <memory>
#include "abstract_scanner.h"
#include "host.h"
#include "interface.h"
#include "ipv4.h"

using namespace std;

class ICMPScanner : public AbstractScanner {
public:
    ICMPScanner(shared_ptr<IPv4> _ipv4, shared_ptr<Interface> _if = nullptr);

    void start();
    void stop();
    map<string, shared_ptr<Host>> get_hosts();

private:
    bool keep_scanning = true;
    shared_ptr<IPv4> network;
    shared_ptr<Interface> interface;
    int rcv_sd;
    int snd_sd;

    void prepare();
    void bind_sockets();
    void recv_responses();
    void send_request(shared_ptr<IPv4> _ipv4, int count);
};

#endif
