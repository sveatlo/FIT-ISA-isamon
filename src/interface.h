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

/**
 * This class represents a local interface
 * @param __name Name of the interface to create
 */
class Interface {
public:
    Interface(string __name);
    ~Interface();


    /**
     * Static method to get all the local interfaces
     * @return [description]
     */
    static set<string> get_all_interfaces();

    /**
     * Get the name of this interface
     * @return name of this interface
     */
    string get_name();

    /**
     * Get the MAC address in the colon notation. Example: 11:22:33:44:55:66
     * @return string representation of mac address
     */
    string get_mac_string();

    /**
     * Get the MAC address as a bitset
     * @return bitset representing the mac address
     */
    bitset<MAC_BITLENGTH> get_mac_address();

    /**
     * Get a vector of IPv4 addresses
     */
    vector<shared_ptr<IPv4>> get_ipv4_addresses();

    /**
     * Get a vector of IPv6 addresses
     */
    vector<shared_ptr<IPv6>> get_ipv6_addresses();

    void print_info();

    /**
     * Get the interface's index
     * @return index of the interface
     */
    int get_index();

private:
    /**
     * name of the interface
     */
    string name;

    /**
     * index of the interface
     */
    int index;

    /**
     * mac address of the interface
     */
    shared_ptr<MAC> mac_address = nullptr;

    /**
     * vector of mmultiple IPv4 addresses
     */
    vector<shared_ptr<IPv4>> ipv4_addresses;

    /**
     * vector of multiple IPv6 addresses
     */
    vector<shared_ptr<IPv6>> ipv6_addresses;

    /**
     * Populate all the private attributes by getting information about the interface by name
     */
    void populate_info();
};

#endif
