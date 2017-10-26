#include <numeric>
#include <bitset>
#include <getopt.h>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <signal.h>
#include <sstream>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <unistd.h>
#include "utils.h"
#include "interface.h"
#include "arp_scanner.h"
#include "icmp_scanner.h"
#include "tcp_scanner.h"
#include "udp_scanner.h"

using namespace std;

void print_help();
void print_hosts();
void interrupt_handler(int type);

bool interrupted = false;
vector<pair<shared_ptr<AbstractScanner>, shared_ptr<thread>>> scanners; // vector of pairs of scanner and its thread
map<string, shared_ptr<Host>> live_hosts; // vector of live (responding) hosts found using one of the techniques below

int main (int argc, char **argv) {
    if(getuid()) {
        Utils::print_error(0);
    }


    int c;
    bool arg_tcp = false, arg_udp = false;
    int arg_wait = -1;
    vector<int> ports;
    string arg_interface, arg_network;

    while (1) {
        static struct option long_options[] = {
            {"tcp", no_argument, 0, 't'},
            {"udp", no_argument, 0, 'u'},
            {"help", no_argument, 0, 'h'},
            {"interface", required_argument, 0, 'i'},
            {"network", required_argument, 0, 'n'},
            {"port", required_argument, 0, 'p'},
            {"wait", required_argument, 0, 'w'},
            {0, 0, 0, 0}
        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "hi:tup:w:", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case 0:
            /* If this option set a flag, do nothing else now. */
            if (long_options[option_index].flag != 0)
                break;
            printf ("option %s", long_options[option_index].name);
            if (optarg)
                printf (" with arg %s", optarg);
            printf ("\n");
            break;

        case 'h':
            print_help();
            return 0;
            break;

        case 'i':
            arg_interface = string(optarg);
            break;

        case 'n':
            arg_network = string(optarg);
            break;

        case 'p':
            try {
                ports.push_back(stoi(optarg));
            } catch (...) {
                Utils::print_error(1);
            }
            break;

        case 'w':
            try {
                arg_wait = stoi(optarg);
            } catch (...) {
                Utils::print_error(1);
            }
            break;

        case 't':
            arg_tcp = true;
            break;

        case 'u':
            arg_udp = true;
            break;
        }
    }

    /* Print any remaining command line arguments (not options). */
    if (optind < argc) {
        print_help();
        Utils::print_error(1);
    }

    (void)arg_wait;

    signal(SIGINT, interrupt_handler);

    shared_ptr<IPv4> relevant_ipv4 = nullptr;
    if (arg_network != "") {
        string relevant_network_ip = "";
        size_t relevant_network_netmask = 0;

        size_t pos = arg_network.find("/");
        if (pos == string::npos) {
            Utils::print_error(1, "Specified network is not in a valid format. Try something like 127.0.0.1/8");
        }

        try {
            relevant_network_netmask = stoul(arg_network.substr(pos + 1));
            relevant_network_ip = arg_network.substr(0, pos);
        } catch(...) {
            Utils::print_error(1, "Specified network is not in a valid format. Try something like 127.0.0.1/8");
        }

        bitset<IPV4_BITLENGTH> relevant_netmask, relevant_address;
        for (size_t i = 0; i < relevant_network_netmask; i++) {
            relevant_netmask.set(IPV4_BITLENGTH - i - 1);
        }
        relevant_address = bitset<IPV4_BITLENGTH>(Utils::ip_to_int(relevant_network_ip));
        relevant_ipv4 = make_shared<IPv4>(relevant_address, relevant_netmask);
    }

    //get all relevant interfaces
    vector<pair<shared_ptr<Interface>, bool>> interfaces;
    bool any_has_network = false;
    set<string> all_interfaces;
    if (arg_interface == "") {
        all_interfaces = Interface::get_all_interfaces();
    } else {
        all_interfaces.insert(arg_interface);
    }
    for (auto interface_name : all_interfaces) {
        auto interface = make_shared<Interface>(interface_name);
        bool has_network = true;
        if (relevant_ipv4 != nullptr) {
            has_network = false;
            for (auto ipv4 : interface->get_ipv4_addresses()) {
                if(ipv4->get_network_address() == relevant_ipv4->get_network_address()) {
                    has_network = true;
                    break;
                }
            }
        }
        any_has_network |= has_network;
        interfaces.push_back(make_pair(interface, has_network));
    }

    if (any_has_network) {
        // one of the NICs is directly connected to the desired network => ARP requests
        for (auto interface : interfaces) {
            if(any_has_network && !interface.second) {
                continue;
            }

            cerr << "\033[1;36;1m[INFO] Starting ARP scan for interface " << interface.first->get_name() << " \033[0m\n";
            shared_ptr<AbstractScanner> scanner;
            scanner = static_pointer_cast<AbstractScanner>(make_shared<ARPScanner>(interface.first));

            scanners.push_back(make_pair(scanner, make_shared<thread>(&AbstractScanner::start, scanner)));
        }
    } else if (relevant_ipv4 != nullptr) {
        // no NIC is directly connected to the desired network => ICMP echo requests
        cerr << "\033[1;36;1m[INFO] Starting ICMP scan\033[0m\n";
        shared_ptr<AbstractScanner> scanner;
        scanner = static_pointer_cast<AbstractScanner>(make_shared<ICMPScanner>(relevant_ipv4));

        scanners.push_back(make_pair(scanner, make_shared<thread>(&AbstractScanner::start, scanner)));
    }

    for(auto scanner : scanners) {
        scanner.second->join();
        auto scanner_result = scanner.first->get_hosts();
        live_hosts.insert(scanner_result.begin(), scanner_result.end());
    }
    cerr << "\033[1;36;1m[INFO] Finished scanning for live hosts. Found " << live_hosts.size() << " live hosts:\033[0m\n";

    if(interrupted) {
        print_hosts();
        return 0;
    }

    scanners.clear();

    // prepare ports to be scanned
    if (ports.size() == 0) {
        ports.resize(65536);
        iota(ports.begin(), ports.end(), 1);
    }

    mutex hosts_mtx;
    if(arg_tcp) {
        cerr << "\033[1;36;1m[INFO] Starting TCP PORT scan\033[0m\n";
        // start tcp scanner
        shared_ptr<AbstractScanner> scanner = static_pointer_cast<AbstractScanner>(make_shared<TCPScanner>(live_hosts, ports, &hosts_mtx));
        scanners.push_back(make_pair(scanner, make_shared<thread>(&AbstractScanner::start, scanner)));
    }
    if (arg_udp) {
        // start udp scanner
        // shared_ptr<AbstractScanner> scanner = static_pointer_cast<AbstractScanner>(make_shared<UDPScanner>(live_hosts, ports, &hosts_mtx));
        // scanners.push_back(make_pair(scanner, make_shared<thread>(&AbstractScanner::start, scanner)));
    }

    // wait for them to join back
    for(auto scanner : scanners) {
        scanner.second->join();
        auto scanner_result = scanner.first->get_hosts();
        live_hosts.insert(scanner_result.begin(), scanner_result.end());
    }

    // PRINT OUT ALL HOSTS AND THEIR INFO
    print_hosts();
    return 0;
}

void print_help() {
    cout << "isamon [-h] [-i <interface>] [-t] [-u] [-p <port>] [-w <ms>] -n <net_address/mask>" << endl;
    cout << "\t-h --help -- zobrazí nápovědu" << endl;
    cout << "\t-i --interface <interface> -- rozhraní na kterém bude nástroj scanovat" << endl;
    cout << "\t-n --network <net_address/mask> -- ip adresa síťe s maskou definující rozsah pro scanování" << endl;
    cout << "\t-t --tcp -- použije TCP" << endl;
    cout << "\t-u --udp -- použije UDP" << endl;
    cout << "\t-p --port <port> -- specifikace scanovaného portu, pokud není zadaný, scanujte celý rozsah" << endl;
    cout << "\t-w --wait <ms> -- dodatečná informace pro Váš nástroj jaké je maximální přípustné RTT" << endl;
}

void print_hosts() {
    for (auto host : live_hosts) {
        host.second->print_info();
    }
}


void interrupt_handler(int type) {
    if (type != SIGINT) {
        return;
    }

    for(auto scanner : scanners) {
        scanner.first->stop();
    }
    interrupted = true;
}
