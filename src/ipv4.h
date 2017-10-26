#ifndef IPV4_H
#define IPV4_H

#include <string>
#include <string.h>
#include <bitset>
#include "definitions.h"

using namespace std;

class IPv4 {
public:
    IPv4(unsigned char* _address, unsigned char* _netmask);
    IPv4(bitset<IPV4_BITLENGTH> _address, bitset<IPV4_BITLENGTH> _netmask); // preferred

    bitset<IPV4_BITLENGTH> get_address();
    bitset<IPV4_BITLENGTH> get_netmask();
    bitset<IPV4_BITLENGTH> get_network_address();
    bitset<IPV4_BITLENGTH> get_broadcast_address();
    string get_address_string();
    string get_netmask_string();
    string get_network_address_string();
    string get_broadcast_address_string();
    uint32_t to_uint32();
private:
    bitset<IPV4_BITLENGTH> address;
    bitset<IPV4_BITLENGTH> netmask;
    string address_string;
    string netmask_string;

    void generate_strings();
};
#endif
