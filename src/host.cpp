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

void Host::add_open_port(int port_no, bool is_tcp, bool is_udp) {
    if(this->ports.find(port_no) == this->ports.end()) {
        this->ports[port_no].second = true;
    }

    this->ports[port_no].first |= is_tcp;
    this->ports[port_no].second &= is_udp;
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
    size_t n = 0;
    for (auto address : this->ipv4) {
        cout << address.second->get_address_string() << (n == this->ipv4.size() - 1 ? "" : ", ");
        n++;
    }
    cout << (this->ports.size() > 0 ? ": \n" : "\n");
    for (auto port : this->ports) {
        cout << "  " << port.first << ": ";
        if (port.second.first) {
            cout << "TCP";

            struct servent* service = getservbyport(port.second.first, "TCP");
            if(service) {
                cout << "(" << service->s_name << ")";
            }

            cout << (!port.second.second ? "+" : "");
        }
        if (!port.second.second) {
            cout << "UDP";

            struct servent* service = getservbyport(port.second.second, "UDP");
            if(service) {
                cout << "(" << service->s_name << ")";
            }
        }
        cout << endl;
    }
}
