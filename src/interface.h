#ifndef INTERFACE_H
#define INTERFACE_H

#include <bitset>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include "definitions.h"
#include "ipv4.h"
#include "ipv6.h"
#include "mac.h"

using namespace std;

class Interface {
public:
    Interface(string __name);
    ~Interface();

    string get_name();
    string get_mac_string();
    vector<shared_ptr<IPv4>> get_ipv4_addresses();
    vector<shared_ptr<IPv6>> get_ipv6_addresses();

    static set<string> get_all_interfaces();
    void print_info();
    bitset<MAC_BITLENGTH> get_mac_address();
    int get_index();

private:
    string name;
    int index;
    shared_ptr<MAC> mac_address;
    vector<shared_ptr<IPv4>> ipv4_addresses;
    vector<shared_ptr<IPv6>> ipv6_addresses;

    void populate_info();
};

#endif
