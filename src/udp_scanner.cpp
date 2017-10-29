#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <iostream>
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
    iph->id = htons(54123);
    iph->frag_off = htons(16384);
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->check = Utils::checksum((unsigned short *) this->buffer, iph->tot_len >> 1);

    //TCP Header
    udph->source = htons(47823);
    udph->len = htons(8);
    udph->check = 0;
}

void UDPScanner::bind_sockets() {
    if ((this->snd_sd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        Utils::print_error(104);
    }

    // int on = 1;
    // if (setsockopt(this->snd_sd, IPPROTO_IP, IP_HDRINCL, (const int*)&on, sizeof(on)) < 0) {
    //     Utils::print_error(104);
    // }

    if ((this->rcv_sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        Utils::print_error(104);
    }
}

void UDPScanner::scan_host(shared_ptr<IPv4> ipv4) {
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

        udph->dest = htons(port);

        psh.saddr = iph->saddr;
        psh.daddr = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.proto = IPPROTO_UDP;
        psh.len = htons( sizeof(struct udphdr) );

        memcpy(&psh.data.udp, udph, sizeof (struct udphdr));
        udph->check = Utils::checksum((unsigned short*)&psh, sizeof(struct pseudo_header));

        //Send the packet
        if (sendto(this->snd_sd, udph, sizeof(struct udphdr), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            Utils::print_error(104);
        }

        usleep(1.5*1000*1000);
        Utils::progress_bar(float(this->cnt++) / (float)this->total);
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
                Utils::print_error(106);
            }
        }

        struct iphdr *ip = (struct iphdr*)ether_frame;
        struct icmphdr *icmp = (struct icmphdr*)ether_frame+ip->ihl*4;

        // BUG: ICMP msg TTL exceeded still gets throug this
        // TODO: fix
        if(ip->protocol != IPPROTO_ICMP && icmp->type != ICMP_ECHOREPLY) {
            continue;
        }

        cout << "RECEIVED ICMP MESSAGE" << endl;
    }

    free(ether_frame);
}
