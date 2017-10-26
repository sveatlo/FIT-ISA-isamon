#include <arpa/inet.h>
#include <ifaddrs.h>
#include <iostream>
#include <linux/if_packet.h>
#include <net/if.h> /* the L2 protocols */
#include <sys/ioctl.h>
#include <unistd.h>

#include "interface.h"
#include "utils.h"

using namespace std;

Interface::Interface(string __name) {
    this->name = __name;
    this->populate_info();
}

Interface::~Interface() {}

string Interface::get_name() {
    return this->name;
}

set<string> Interface::get_all_interfaces() {
    set<string> res;

    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) != 0) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    struct ifaddrs * ifa;
    int n;
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (!ifa->ifa_addr || !ifa->ifa_addr->sa_family) {
            continue;
        }

        res.insert(string(ifa->ifa_name));
    }

    freeifaddrs(ifaddr);

    return res;
}

void Interface::populate_info() {
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) != 0) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    struct ifaddrs * ifa;
    int n;
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if(!ifa->ifa_addr || !ifa->ifa_addr->sa_family) {
            continue;
        }
        int family = ifa->ifa_addr->sa_family;
        if(string(ifa->ifa_name) != this->name || ifa->ifa_addr == NULL) {
            continue;
        }

        switch (family) {
            case AF_PACKET:
                {
                    // save struct containing MAC address
                    struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                    // copy mac address to instance variable
                    unsigned char cmac[MAC_LENGTH] = {};
                    memcpy(cmac, s->sll_addr, MAC_LENGTH);
                    this->mac_address = make_shared<MAC>(cmac);
                    break;
                }
            case AF_INET:
                {
                    unsigned char address[IPV4_LENGTH], netmask[IPV4_LENGTH];
                    // copy ipv4 addr
                    memcpy(address, &(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr), IPV4_LENGTH);
                    // process netmask
                    memcpy(netmask, (ifa->ifa_netmask->sa_data) + 2, IPV4_LENGTH);

                    this->ipv4_addresses.push_back(make_shared<IPv4>(address, netmask));

                    break;
                }
            case AF_INET6:
                {
                    //copy ipv6 address
                    unsigned char ipv6_address_arr[IPV6_LENGTH];
                    memcpy(ipv6_address_arr, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, IPV6_LENGTH);
                    //create ipv6 string
                    char address[INET6_ADDRSTRLEN];
                    inet_ntop(family, &((sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, address, sizeof(address));
                    string ipv6_string = string(address);

                    //if start with fe80 => is link-local
                    if(ipv6_string.find("fe80") == 0) {
                        this->ipv6_addresses.push_back(make_shared<IPv6>(ipv6_address_arr, ipv6_string));
                    }

                    break;
                }
        }
    }
    freeifaddrs(ifaddr);

    // get interface index
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, 0);
    if (sd <= 0) {
        Utils::print_error(101);
    }
    if (this->name.length() > (IFNAMSIZ - 1)) {
        Utils::print_error(101);
    }
    strcpy(ifr.ifr_name, this->name.c_str());

    //Get interface index using name
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        if (sd > 0) {
            close(sd);
        }
        Utils::print_error(101);
    }
    this->index = ifr.ifr_ifindex;

    close(sd);
}

bitset<MAC_BITLENGTH> Interface::get_mac_address() {
    return this->mac_address->value();
}

string Interface::get_mac_string() {
    return this->mac_address->to_string();
}

int Interface::get_index() {
    return this->index;
}

void Interface::print_info() {
    cout << "Interface info: " << endl;
    cout << "\tName: " << this->name << endl;
    cout << "\tInterface index: " << this->index << endl;
    cout << "\tMAC address: " << this->get_mac_string() << endl;
    for(auto &ipv4_address : this->ipv4_addresses) {
        cout << "\tIPv4 address: " << ipv4_address->get_address_string() << endl;
        cout << "\tIPv4 netmask: " << ipv4_address->get_netmask_string() << endl;
    }
    for(auto &ipv6_address : this->ipv6_addresses) {
        cout << "\tIPv6 address: " << ipv6_address->get_address_string() << endl;
    }
}

vector<shared_ptr<IPv4>> Interface::get_ipv4_addresses() {
    return this->ipv4_addresses;
}

vector<shared_ptr<IPv6>> Interface::get_ipv6_addresses() {
    return this->ipv6_addresses;
}
