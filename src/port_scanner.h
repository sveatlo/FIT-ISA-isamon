#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include "host.h"
#include "abstract_scanner.h"

using namespace std;

class PortScanner : public AbstractScanner {
public:
    PortScanner(map<string, shared_ptr<Host>> &_hosts, vector<int> &_ports, mutex* _hosts_mutex);

    void start();
    void stop();
    map<string, shared_ptr<Host>> get_hosts();

protected:
    int cnt = 0;
    int total = 1;
    bool keep_scanning = 1;
    int rcv_sd;
    int snd_sd;
    vector<int> ports;
    mutex* hosts_mutex;

    virtual void prepare() =0;
    virtual void scan_host(shared_ptr<IPv4>) =0;
    virtual void recv_responses() =0;
};

#endif
