#include <arpa/inet.h>
#include <bitset>
#include <iostream>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include "definitions.h"
#include "utils.h"
#include "icmp_scanner.h"


ICMPScanner::ICMPScanner(shared_ptr<IPv4> _ipv4, int _wait, shared_ptr<Interface> _if) {
    this->network = _ipv4;
    this->wait = _wait == -1 ? this->wait : _wait;
    this->interface = _if;
}

void ICMPScanner::start() {
    this->prepare();
    thread t(&ICMPScanner::recv_responses, this);
    this->total = this->network->get_broadcast_address().to_ulong() - this->network->get_network_address().to_ulong();
    if (this->total == 0) {
        this->total = 1;
        this->send_request(make_shared<IPv4>(this->network->get_broadcast_address(), this->network->get_netmask()), 0);
        this->scanned++;
    } else if(this->total > 2) {
        this->total -= 2;
        for(auto dst = Utils::increment(this->network->get_network_address()); dst < this->network->get_broadcast_address() && this->keep_scanning; dst = Utils::increment(dst)) {
            this->send_request(make_shared<IPv4>(dst, this->network->get_netmask()), 0);

            this->scanned++;
            // usleep(1000); // protects before running out of buffer space
        }
    }
    usleep(this->wait*1000);
    this->stop();
    t.join();
}

void ICMPScanner::stop() {
    this->keep_scanning = false;
    shutdown(this->rcv_sd, SHUT_RDWR);
    shutdown(this->snd_sd, SHUT_RDWR);
}

void ICMPScanner::prepare() {
    this->bind_sockets();
}

void ICMPScanner::bind_sockets() {
    if ((this->snd_sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        Utils::print_error(105);
    }

    if(this->interface != nullptr) {
        struct ifreq ifr;

        memset(&ifr, 0, sizeof(ifr));
        if (setsockopt(this->snd_sd, SOL_SOCKET, SO_BINDTODEVICE, this->interface->get_name().c_str(), sizeof(ifr)) < 0) {
            Utils::print_error(105);
        }
    }

    if ((this->rcv_sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        Utils::print_error(106);
    }
}

void ICMPScanner::send_request(shared_ptr<IPv4> dst, int count) {
    unsigned char buffer[MAXPACKET];
    struct icmp* icp = (struct icmp*)buffer;
    int len = 64;

    icp->icmp_type = ICMP_ECHO;
    icp->icmp_code = 0;
    icp->icmp_cksum = 0;
    icp->icmp_seq = count;
    icp->icmp_id = getpid();

    icp->icmp_cksum = Utils::checksum((uint16_t*)icp, len);

    struct sockaddr_in to;
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = inet_addr(dst->get_address_string().c_str());

    uint8_t retries_cnt = 0;
    while(true) {
        retries_cnt++;
        if (retries_cnt >= 4) {
            Utils::log_info("Giving up after 3rd retry.");
            Utils::print_error(105, "No buffer space available");
        }

        // Send the packet
        if (sendto(this->snd_sd, buffer, len, 0, (struct sockaddr*)&to, sizeof(struct sockaddr)) < 0)  {
            int my_err = errno;
            if(my_err == EACCES) {
                Utils::log_warn("Cannot send ICMP request to " + dst->get_address_string() + ". Maybe broadcast address for subnet?");
                break;
            } else if (my_err == ENOBUFS) {
                Utils::log_warn("Ran out of buffer space, retrying after 5s");
                usleep(5000 * 1000);
            } else {
                Utils::print_error(105);
                break; // useless, but nice
            }
        } else {
            break;
        }
    }
    this->ips_scanned.insert(dst->get_address_string());
}

void ICMPScanner::recv_responses() {
    int status = 0;
    uint8_t *ether_frame = (uint8_t *) malloc (IP_MAXPACKET * sizeof (uint8_t));
    if(ether_frame == NULL) {
        Utils::print_error(106);
    }
    while(this->keep_scanning) {
        bzero(ether_frame, sizeof(ether_frame));

        if((status = recv(this->rcv_sd, ether_frame, IP_MAXPACKET, 0)) < 0) {
            if(errno == EINTR) {
                continue; // Something weird happened, but let's try again.
            } else {
                Utils::print_error(106);
            }
        }

        struct iphdr *ip = (struct iphdr*)ether_frame;
        struct icmphdr *icmp = (struct icmphdr*)ether_frame+ip->ihl*4;

        // skip if protocol isn't ICMP or ICMP response isn't an echo response
        if(ip->protocol != IPPROTO_ICMP || icmp->type != ICMP_ECHOREPLY) {
            continue;
        }


        shared_ptr<IPv4> ipv4 = make_shared<IPv4>(bitset<IPV4_BITLENGTH>(ntohl(ip->saddr)), this->network->get_netmask());
        if (this->hosts.find(ipv4->get_address_string()) == this->hosts.end() &&
                this->ips_scanned.find(ipv4->get_address_string()) != this->ips_scanned.end()) {
            shared_ptr<Host> host = make_shared<Host>();
            host->add_ipv4(ipv4);
            this->hosts[ipv4->get_address_string()] = host;
        }
    }

    free(ether_frame);
}
