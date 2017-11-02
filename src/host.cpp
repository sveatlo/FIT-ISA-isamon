#include <arpa/inet.h>
#include <netdb.h>
#include <iostream>
#include "host.h"

Host::Host() {}

Host::Host(shared_ptr<MAC> _mac) {
    this->mac = _mac;
}

void Host::add_ipv4(shared_ptr<IPv4> _ipv4) {
    string key = _ipv4->get_address_string() + "/" + _ipv4->get_netmask_string();
    if (this->ipv4.find(key) == this->ipv4.end()) {
        this->ipv4[key] = _ipv4;
    }
}

void Host::set_tcp_port(int port_no, bool open) {
    this->ports[port_no].first = open;
}

void Host::set_udp_port(int port_no, bool open) {
    this->ports[port_no].second = open;
}


void Host::set_mac(shared_ptr<MAC> _mac) {
    this->mac = _mac;
}

shared_ptr<MAC> Host::get_mac() {
    return this->mac;
}

map<string, shared_ptr<IPv4>> Host::get_ipv4_addresses() {
    return this->ipv4;
}

void Host::print_info() {
    // size_t n = 0;
    // for (auto address : this->ipv4) {
    //     cout << address.second->get_address_string() << (n == this->ipv4.size() - 1 ? "" : ", ");
    //     n++;
    // }
    // cout << (this->ports.size() > 0 ? ": \n" : "\n");
    // for (auto port : this->ports) {
    //     if (!port.second.first && !port.second.second) {
    //         continue;
    //     }
    //
    //     cout << "  " << port.first << ": ";
    //     if (port.second.first) {
    //         cout << "TCP";
    //
    //         struct servent* service = getservbyport(port.second.first, "TCP");
    //         if(service) {
    //             cout << "(" << service->s_name << ")";
    //         }
    //
    //         cout << (port.second.second ? "+" : "");
    //     }
    //     if (port.second.second) {
    //         cout << "UDP";
    //
    //         struct servent* service = getservbyport(port.second.second, "UDP");
    //         if(service) {
    //             cout << "(" << service->s_name << ")";
    //         }
    //     }
    //     cout << endl;
    // }

    // fking ugly output required by the project assignment
    cout << this->ipv4.begin()->second->get_address_string() << endl;
    for (auto port : this->ports) {
        if(port.second.first) {
            cout << this->ipv4.begin()->second->get_address_string() << " TCP "
                    << port.first
                    << endl;
        }

        if(port.second.second) {
            cout << this->ipv4.begin()->second->get_address_string() << " UDP "
                    << port.first
                    << endl;
        }
    }
}
