#ifndef HOST_H
#define HOST_H

#include <map>
#include <memory>
#include "ipv4.h"
#include "ipv6.h"
#include "mac.h"

using namespace std;

class Host {
public:
    Host();
    Host(shared_ptr<MAC>);

    void set_mac(shared_ptr<MAC> _mac);
    void add_ipv4(shared_ptr<IPv4> _ipv4);
    void add_open_port(int port_no, bool is_tcp = false, bool is_udp = true);
    shared_ptr<MAC> get_mac();
    map<string, shared_ptr<IPv4>> get_ipv4_addresses();
    void print_info();

private:
    map<string, shared_ptr<IPv4>> ipv4;
    map<string, shared_ptr<IPv6>> ipv6;
    shared_ptr<MAC> mac;
    map<int, pair<bool, bool>> ports; // 53:[TCP=1,UDP=1]
};

#endif
