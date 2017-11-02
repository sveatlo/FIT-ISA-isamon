#include <arpa/inet.h>
#include <iostream>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include "udp_scanner.h"
#include "utils.h"


void UDPScanner::prepare() {
    this->bind_sockets();

    struct iphdr *iph = (struct iphdr*)this->buffer;
    struct udphdr *udph = (struct udphdr*)(this->buffer + sizeof (struct iphdr));

    memset (this->buffer, 0, sizeof(this->buffer));

    char source_ip[20];
    Utils::get_local_ip(source_ip);

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct udphdr);
    iph->frag_off = htons(16384);
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->check = Utils::checksum((unsigned short *) this->buffer, iph->tot_len >> 1);

    //TCP Header
    udph->len = htons(8);
    udph->check = 0;
}

void UDPScanner::bind_sockets() {
    if ((this->snd_sd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        Utils::print_error(109);
    }

    // int on = 1;
    // if (setsockopt(this->snd_sd, IPPROTO_IP, IP_HDRINCL, (const int*)&on, sizeof(on)) < 0) {
    //     Utils::print_error(104);
    // }
    if(this->interface != nullptr) {
        struct ifreq ifr;

        memset(&ifr, 0, sizeof(ifr));
        if (setsockopt(this->snd_sd, SOL_SOCKET, SO_BINDTODEVICE, this->interface->get_name().c_str(), sizeof(ifr)) < 0) {
            Utils::print_error(109);
        }
    }

    if ((this->rcv_sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        Utils::print_error(110);
    }
}

void UDPScanner::scan_host(shared_ptr<Host> &host, shared_ptr<IPv4> &ipv4) {
    static int port_counter = 0;

    char datagram[sizeof(this->buffer)];
    memcpy(datagram, this->buffer, sizeof(this->buffer));
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof (struct iphdr));

    struct pseudo_header psh;
    struct sockaddr_in dest;
    struct in_addr dest_ip = {
        .s_addr = inet_addr(ipv4->get_address_string().c_str())
    };
    iph->daddr = dest_ip.s_addr;

    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip.s_addr;

    for(auto port : this->ports) {
        if (!this->keep_scanning) {
            break;
        }

        iph->id = htons(getuid() + (++port_counter));
        iph->check = 0;

        udph->dest = htons(port);
        udph->source = htons(rand() % 4096 + 61440);
        udph->check = 0;

        psh.saddr = iph->saddr;
        psh.daddr = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.proto = IPPROTO_UDP;
        psh.len = htons( sizeof(struct udphdr) );

        memcpy(&psh.data.udp, udph, sizeof (struct udphdr));
        udph->check = Utils::checksum((unsigned short*)&psh, sizeof(struct pseudo_header));

        //Send the packet
        if (sendto(this->snd_sd, udph, sizeof(struct udphdr), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            Utils::print_error(109);
        }

        this->hosts_mutex->lock();
        host->set_udp_port(port, true);
        this->hosts_mutex->unlock();

        this->scanned++;
        usleep(this->wait*1000);
    }
}

void UDPScanner::recv_responses() {
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
                Utils::print_error(110);
            }
        }

        struct iphdr *ip = (struct iphdr*)ether_frame;
        struct icmphdr *icmp = (struct icmphdr*)(ether_frame + ip->ihl*4);

        if(ip->protocol != IPPROTO_ICMP || icmp->type != ICMP_DEST_UNREACH) {
            continue;
        }

        // *(struct udphdr*)(icmp + sizeof(struct icmphdr) + sizeof(struct iphdr))
        // *(struct iphdr*)(icmp + sizeof(struct icmphdr))

        struct iphdr *ip2 = (struct iphdr*)(((uint8_t*)icmp) + sizeof(struct icmphdr));
        struct udphdr *udp = (struct udphdr*)(((uint8_t*)ip2) + ip2->ihl*4);

        unsigned char ip_arr[IPV4_LENGTH];
        unsigned long uip = ntohl(ip->saddr);
        unsigned char* p = (unsigned char*)&uip;
        for (int i = 0; i < IPV4_LENGTH; i++) {
            ip_arr[i] = p[IPV4_LENGTH - 1 - i];
        }
        auto source_ip = make_shared<IPv4>(ip_arr, nullptr);
        if(this->hosts.find(source_ip->get_address_string()) != this->hosts.end()) {
            this->hosts_mutex->lock();
            this->hosts[source_ip->get_address_string()]->set_udp_port(ntohs(udp->dest), false);
            this->hosts_mutex->unlock();
        }
    }

    free(ether_frame);
}
