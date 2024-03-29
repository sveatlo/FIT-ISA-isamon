#include <iostream>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>
#include "port_scanner.h"

PortScanner::PortScanner(map<string, shared_ptr<Host>> &_hosts, vector<int> &_ports, mutex* _hosts_mutex, int _wait, shared_ptr<Interface> _if) {
    this->hosts = _hosts;
    this->hosts_mutex = _hosts_mutex;
    this->ports = _ports;
    this->total = this->hosts.size()*this->ports.size() - 1;
    this->wait = _wait == -1 ? this->wait : _wait;
    this->interface = _if;
}


void PortScanner::start() {
    this->prepare();
    thread t(&PortScanner::recv_responses, this);
    for (auto host : this->hosts) {
        if (!this->keep_scanning) {
            break;
        }

        for(auto ipv4 : host.second->get_ipv4_addresses()) {
            this->scan_host(host.second, ipv4.second);
        }
    }

    usleep(this->wait*1000);
    this->stop();
    t.join();
}

void PortScanner::stop() {
    this->keep_scanning = false;
    shutdown(this->rcv_sd, SHUT_RDWR);
    shutdown(this->snd_sd, SHUT_RDWR);
}
