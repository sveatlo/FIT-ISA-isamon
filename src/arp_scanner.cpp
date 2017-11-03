#include "arp_scanner.h"
#include "utils.h"


ARPScanner::ARPScanner(shared_ptr<Interface> _interface, int _wait) {
    this->interface = _interface;
    this->wait = _wait == -1 ? this->wait : _wait;

    // this->interface->print_info();
}

void ARPScanner::start() {
    this->prepare();
    thread t(&ARPScanner::recv_responses, this);

    this->total = 0;
    this->scanned = 0;
    // multiple ARP request proven efficient with misbehaving/cheap android devices
    int retries = 3;
    for (int i = 0; i < retries + 1; i++) {
        for(auto &src : this->interface->get_ipv4_addresses()) {
            this->total += src->get_broadcast_address().to_ulong() - src->get_network_address().to_ulong() - 2;
        }
    }

    for (int i = 0; i < retries + 1 && this->keep_scanning; i++) {
        for(auto &src : this->interface->get_ipv4_addresses()) {
            if (!this->keep_scanning) {
                break;
            }

            for(auto dst = src->get_network_address();
                dst < src->get_broadcast_address() && this->keep_scanning;
                dst = Utils::increment(dst)
            ) {
                auto dst_ipv4 = make_shared<IPv4>(dst, src->get_netmask());
                if (dst != src->get_address()) {
                    this->send_request(src, dst_ipv4);
                }

                this->scanned++;
            }
        }
        usleep(this->wait*1000);
    }
    this->stop();
    t.join();
}

void ARPScanner::stop() {
    this->keep_scanning = false;
    shutdown(this->rcv_sd, SHUT_RDWR);
}

void ARPScanner::bind_sockets() {
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = this->interface->get_index();

    // Submit request for a raw socket descriptor.
    this->snd_sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (this->snd_sd <= 0) {
        Utils::print_error(102);
    }
    if (bind(this->snd_sd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        if(this->snd_sd > 0) {
            close(this->snd_sd);
        }
        Utils::print_error(102);
    }


    if ((this->rcv_sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        Utils::print_error(104);
    }
    if (bind(this->rcv_sd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        if(this->rcv_sd > 0) {
            close(this->rcv_sd);
        }
        Utils::print_error(102);
    }

    // TODO: fix non-working receiving timeout
    // struct timeval wait;
    // wait.tv_sec  = 2;
    // wait.tv_usec = 0;
    // //set socket timeout
    // if(setsockopt(this->rcv_sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&wait, sizeof(struct timeval)) < 0) {
    //     Utils::print_error(104);
    // }
}

void ARPScanner::recv_responses()  {
    int status = 0;
    uint8_t ether_frame[IP_MAXPACKET];
    if(ether_frame == NULL) {
        Utils::print_error(104);
    }
    while (this->keep_scanning) {
        memset(ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
        if((status = recv(this->rcv_sd, ether_frame, IP_MAXPACKET, 0)) < 0) {
            if(errno == EINTR) {
                continue; // Something weird happened, but let's try again.
            } else if(errno == EAGAIN) {
                break;
            } else {
                Utils::print_error(104);
            }
        }

        struct arp_header *arp_res;
        struct ethhdr *eth_res = (struct ethhdr *) ether_frame;
        arp_res = (struct arp_header *)(ether_frame + ETH2_HEADER_LEN);
        if (ntohs(eth_res->h_proto) != PROTO_ARP || ntohs(arp_res->opcode) != ARP_REPLY) {
            // skip if not ARP reply
            continue;
        }

        unsigned char src_mac_cstring[MAC_LENGTH] = {};
        memcpy(src_mac_cstring, &ether_frame[6], MAC_LENGTH);
        auto src_mac_address = make_shared<MAC>(src_mac_cstring);
        if(src_mac_address->to_string() == this->interface->get_mac_string()) {
            continue; // ignore replies from this node
        }

        auto sender_ipv4 = make_shared<IPv4>(arp_res->sender_ip, nullptr);
        if (this->hosts.find(sender_ipv4->get_address_string()) == this->hosts.end()) {
            // not found
            auto host = make_shared<Host>();
            host->set_mac(src_mac_address);
            host->add_ipv4(sender_ipv4);
            this->hosts[sender_ipv4->get_address_string()] = host;
        }


        // cout << "Received ARP response:" << endl;
        // // cout << "\tDestination MAC (this node): " << dst_mac_string << endl;
        // cout << "\tSource MAC: " << src_mac_address->to_string() << endl;
        // // Next is ethernet type code (ETH_P_ARP fo
        // cout << "\tEthernet type code (2054 = ARP): " << ((ether_frame[12]) << 8) + ether_frame[13] << endl;
        // cout << "\tEthernet data (ARP header):\n";
        // cout << "\t\tHardware type (1 = ethernet (10 Mb)): " << ntohs(arp_res->hardware_type) << endl;
        // cout << "\t\tProtocol type (2048 for IPv4 addresses): " << ntohs(arp_res->protocol_type) << endl;
        // cout << "\t\tHardware (MAC) address length (bytes): " << arp_res->hardware_len << endl;
        // cout << "\t\tProtocol (IPv4) address length (bytes): " << arp_res->protocol_len << endl;
        // cout << "\t\tOpcode (2 = ARP reply): " << ntohs(arp_res->opcode) << endl;
        // // cout << "Sender protocol (IPv4) address: " << inet_ntoa(sender_ip_struct) << endl;
    }
}

void ARPScanner::prepare() {
    this->bind_sockets();

    memset(this->buffer, 0, sizeof(this->buffer));

    this->socket_address.sll_family = AF_PACKET;
    this->socket_address.sll_protocol = htons(ETH_P_ARP);
    this->socket_address.sll_ifindex = this->interface->get_index();
    this->socket_address.sll_hatype = htons(ARPHRD_ETHER);
    this->socket_address.sll_pkttype = (PACKET_BROADCAST);
    this->socket_address.sll_halen = MAC_LENGTH;
    this->socket_address.sll_addr[6] = 0x00;
    this->socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) this->buffer;
    struct arp_header *arp_req = (struct arp_header *) (this->buffer + ETH2_HEADER_LEN);

    //Broadcast
    memset(send_req->h_dest, 0xff, MAC_LENGTH);

    //Target MAC zero
    memset(arp_req->target_mac, 0x00, MAC_LENGTH);

    //Set source mac to our MAC address
    unsigned char mac_arr[MAC_LENGTH];
    unsigned long umac = this->interface->get_mac_address().to_ulong();
    unsigned char* p = (unsigned char*)&umac;
    for (int i = 0; i < MAC_LENGTH; i++) {
        mac_arr[i] = p[MAC_LENGTH - 1 - i];
    }

    memcpy(send_req->h_source, &mac_arr, MAC_LENGTH);
    memcpy(arp_req->sender_mac, &mac_arr, MAC_LENGTH);
    memcpy(this->socket_address.sll_addr, &mac_arr, MAC_LENGTH);

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->hardware_type = htons(HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);
}

void ARPScanner::send_request(shared_ptr<IPv4> src, shared_ptr<IPv4> dst) {
    unsigned char my_buffer[BUF_SIZE];
    memcpy(my_buffer, this->buffer, BUF_SIZE);

    struct arp_header *arp_req = (struct arp_header *) (my_buffer + ETH2_HEADER_LEN);

    uint32_t src_ip = htonl(src->to_uint32());
    uint32_t dst_ip = htonl(dst->to_uint32());
    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    ssize_t ret = sendto(this->snd_sd, my_buffer, 42, 0, (struct sockaddr *)&(this->socket_address), sizeof(this->socket_address));
    if (ret == -1) {
        Utils::print_error(103);
    }
}
