#include <arpa/inet.h>
#include <bitset>
#include <iostream>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include "tcp_scanner.h"
#include "utils.h"


void TCPScanner::prepare() {
    this->bind_sockets();

    struct iphdr *iph = (struct iphdr*)this->buffer;
    struct tcphdr *tcph = (struct tcphdr*)(this->buffer + sizeof (struct iphdr));

    memset (this->buffer, 0, sizeof(this->buffer));

    char source_ip[20];
    Utils::get_local_ip(source_ip);

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = getpid();
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->check = Utils::checksum((unsigned short *) this->buffer, iph->tot_len >> 1);

    //TCP Header
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons (14600);
    tcph->check = 0;
    tcph->urg_ptr = 0;
}

void TCPScanner::bind_sockets() {
    if ((this->snd_sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        Utils::print_error(107);
    }

    int on = 1;
    if (setsockopt(this->snd_sd, IPPROTO_IP, IP_HDRINCL, (const int*)&on, sizeof (on)) < 0) {
        Utils::print_error(107);
    }

    if(this->interface != nullptr) {
        struct ifreq ifr;

        memset(&ifr, 0, sizeof(ifr));
        if (setsockopt(this->snd_sd, SOL_SOCKET, SO_BINDTODEVICE, this->interface->get_name().c_str(), sizeof(ifr)) < 0) {
            Utils::print_error(105);
        }
    }

    if ((this->rcv_sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        Utils::print_error(108);
    }
}

void TCPScanner::scan_host(shared_ptr<Host>& host, shared_ptr<IPv4>& ipv4) {
    (void)host;
    static int port_counter = 0;

    char datagram[sizeof(this->buffer)];
    memcpy(datagram, this->buffer, sizeof(this->buffer));
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof (struct iphdr));

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

        tcph->seq = htonl(rand());
        tcph->source = htons(rand() % 4096 + 61440);
        tcph->dest = htons (port);
        tcph->check = 0;

        psh.saddr = iph->saddr;
        psh.daddr = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.proto = IPPROTO_TCP;
        psh.len = htons( sizeof(struct tcphdr) );

        memcpy(&psh.data.tcp, tcph, sizeof (struct tcphdr));
        tcph->check = Utils::checksum((unsigned short*)&psh, sizeof(struct pseudo_header));

        //Send the packet
        if (sendto(this->snd_sd, datagram, sizeof(struct tcphdr) + sizeof(struct iphdr), 0, (struct sockaddr *) &dest, sizeof (dest)) < 0) {
            Utils::print_error(107);
        }

        Utils::progress_bar(float(this->cnt++) / (float)this->total);
    }
}

void TCPScanner::recv_responses() {
    int status;
    unsigned char buffer[IP_MAXPACKET];

    struct sockaddr addr;
    socklen_t addrl = sizeof(addr);
    while(this->keep_scanning) {
        memset(buffer, 0, IP_MAXPACKET);
        if((status = recvfrom(this->rcv_sd , buffer , 65536 , 0 , &addr , &addrl)) < 0) {
            if(errno == EINTR) {
                continue; // Something weird happened, but let's try again.
            } else if(errno == EAGAIN) {
                break;
            } else {
                Utils::print_error(108);
            }
        }

        struct iphdr* iph = (struct iphdr*)buffer;
        struct tcphdr* tcph=(struct tcphdr*)(buffer + iph->ihl*4);

        if(iph->protocol == 6)
        {
            unsigned char ip_arr[IPV4_LENGTH];
            unsigned long uip = ntohl(iph->saddr);
            unsigned char* p = (unsigned char*)&uip;
            for (int i = 0; i < IPV4_LENGTH; i++) {
                ip_arr[i] = p[IPV4_LENGTH - 1 - i];
            }
            auto source_ip = make_shared<IPv4>(ip_arr, nullptr);

            if(tcph->syn == 1 && tcph->ack == 1 && this->hosts.find(source_ip->get_address_string()) != this->hosts.end()) {
                this->hosts_mutex->lock();
                this->hosts[source_ip->get_address_string()]->set_tcp_port(ntohs(tcph->source), true);
                this->hosts_mutex->unlock();
            }
        }
    }
}
