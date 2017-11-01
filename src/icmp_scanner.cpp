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


ICMPScanner::ICMPScanner(shared_ptr<IPv4> _ipv4, shared_ptr<Interface> _if) {
    this->network = _ipv4;
    this->interface = _if;
}

void ICMPScanner::start() {
    this->prepare();
    thread t(&ICMPScanner::recv_responses, this);
    unsigned long total = this->network->get_broadcast_address().to_ulong() - this->network->get_network_address().to_ulong();
    if (total == 0) {
        this->send_request(make_shared<IPv4>(this->network->get_broadcast_address(), this->network->get_netmask()), 0);
    } else {
        total -= 2;
        unsigned long cnt = 0;
        for(auto dst = Utils::increment(this->network->get_network_address()); dst < this->network->get_broadcast_address() && this->keep_scanning; dst = Utils::increment(dst), cnt++) {
            this->send_request(make_shared<IPv4>(dst, this->network->get_netmask()), 0);
            // Utils::progress_bar((float)cnt / (float)total);
            usleep(1*1000);
        }
        cout << endl << flush;
    }
    usleep(2*1000*1000); // give other nodes 2s to respond
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
        if(this->hosts.find(ipv4->get_address_string()) == this->hosts.end()) {
            shared_ptr<Host> host = make_shared<Host>();
            host->add_ipv4(ipv4);
            this->hosts[ipv4->get_address_string()] = host;
        }
    }

    free(ether_frame);
}

map<string, shared_ptr<Host>> ICMPScanner::get_hosts() {
    return this->hosts;
}

void ICMPScanner::send_request(shared_ptr<IPv4> dst, int count) {
    static int error_counter = 0;
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

    int status = -1;
    if ((status = sendto(this->snd_sd, buffer, len, 0, (struct sockaddr*)&to, sizeof(struct sockaddr))) < 0)  {
        cout << flush << "\r" << endl;
        Utils::log_warn("Cannot send ICMP request to: " + dst->get_address_string() + ": " + strerror(errno));

        error_counter++;
        if (error_counter > 8) {
            Utils::print_error(105, "Too many errors while sending ICMP echo requests");
        }
    }
}
