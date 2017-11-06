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

#define clrscr(); cout << "\x1b[2J\x1b[1;1H" << flush;

using namespace std;

void run(int argc, char** argv);
void print_help();
void print_hosts();
void interrupt_handler(int type);
void show_progress();

bool interrupted = false;
vector<pair<shared_ptr<AbstractScanner>, shared_ptr<thread>>> scanners; // vector of pairs of scanner and its thread
map<string, shared_ptr<Host>> live_hosts; // vector of live (responding) hosts found using one of the techniques below

int main (int argc, char** argv) {
    // clrscr();
    try {
        run(argc, argv);
    } catch(int err) {
        Utils::print_error(err);
    }
}

void run(int argc, char** argv) {

        int c;
        bool arg_tcp = false, arg_udp = false;
        int arg_wait = -1;
        vector<int> ports;
        set<string> all_interfaces;
        string arg_network;

        while (1) {
            static struct option long_options[] = {
                {"help", no_argument, 0, 'h'},
                {"tcp", no_argument, 0, 't'},
                {"udp", no_argument, 0, 'u'},
                {"interface", required_argument, 0, 'i'},
                {"network", required_argument, 0, 'n'},
                {"port", required_argument, 0, 'p'},
                {"wait", required_argument, 0, 'w'},
                {0, 0, 0, 0}
            };
            /* getopt_long stores the option index here. */
            int option_index = 0;

            c = getopt_long(argc, argv, "htui:n:p:w:", long_options, &option_index);

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
                return;
                break;

            case 'i':
                try {
                    all_interfaces.insert(string(optarg));
                } catch(...) {
                    Utils::print_error(1);
                }
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

        if(ports.size() && !(arg_udp || arg_tcp)) {
            Utils::print_error(1, "Ports specified without scanning method.");
        }


        if(getuid()) {
            Utils::print_error(255);
        }

        signal(SIGINT, interrupt_handler);

        // process --network argument
        shared_ptr<IPv4> relevant_ipv4 = nullptr;
        if (arg_network != "") {
            string relevant_network_ip = "";
            size_t relevant_network_netmask = 0;

            size_t pos = arg_network.find("/");
            if (pos == string::npos) {
                // Utils::print_error(1, "Specified network is not in a valid format. Try something like 127.0.0.1/8");
                // assume /32
                arg_network += "/32";
                pos = arg_network.find("/");
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

        // start relevant scans on relevant interfaces
        vector<shared_ptr<Interface>> interfaces;
        map<string, bool> running_arp;

        if (all_interfaces.size() == 0) {
            all_interfaces = Interface::get_all_interfaces();
        }
        // iterate over all interfaces
        for (auto interface_name : all_interfaces) {
            shared_ptr<Interface> interface;
            try {
                interface = make_shared<Interface>(interface_name);
                interfaces.push_back(interface);
            } catch(int) {
                // ignore errored interface
                continue;
            }

            // cout << "Processing interface " << interface_name << endl;
            if (relevant_ipv4 == nullptr) {
                // cout << " (no relevant network) => network ARP SCAN\n";
                // no --network argument => just run ARP scan
                shared_ptr<AbstractScanner> scanner;
                scanner = static_pointer_cast<AbstractScanner>(make_shared<ARPScanner>(interface, arg_wait));
                Utils::log_info("Starting ARP scan on interface " + interface->get_name());

                scanners.push_back(make_pair(scanner, make_shared<thread>(&AbstractScanner::start, scanner)));
                running_arp[interface_name] = true;

                // and do not process addresses
                continue;
            }

            // check all of its ipv4 addresses
            for (auto ipv4 : interface->get_ipv4_addresses()) {
                // cout << "\twith IPv4 address: " << ipv4->get_network_address_string() << "/" << ipv4->get_netmask_string();
                if (
                    running_arp[interface_name] == false &&
                    ipv4->get_network_address() == relevant_ipv4->get_network_address() &&
                    ipv4->get_broadcast_address() == relevant_ipv4->get_broadcast_address()
                ) {
                    // cout << " => network ARP SCAN";
                    // same network => ARP scan
                    shared_ptr<AbstractScanner> scanner;
                    scanner = static_pointer_cast<AbstractScanner>(make_shared<ARPScanner>(interface, arg_wait));
                    Utils::log_info("Starting ARP scan on interface " + interface->get_name());

                    scanners.push_back(make_pair(scanner, make_shared<thread>(&AbstractScanner::start, scanner)));
                    running_arp[interface_name] = true;
                } else {
                    // subnet or totally different network
                    // cout << endl << "\t\t" << (running_arp[interface_name] == false) << endl;
                    // cout << "\t\t" << (ipv4->get_network_address().to_string() > relevant_ipv4->get_network_address().to_string()) << endl;
                    // cout << "\t\t" << (ipv4->get_broadcast_address().to_string() > relevant_ipv4->get_broadcast_address().to_string()) << endl << endl;
                    // cout << ipv4->get_network_address_string() << " vs " << relevant_ipv4->get_network_address_string() << endl;
                    // cout << ipv4->get_broadcast_address_string() << " vs " << relevant_ipv4->get_broadcast_address_string() << endl;
                    if (
                        running_arp[interface_name] == false &&
                        ipv4->get_network_address().to_string() >= relevant_ipv4->get_network_address().to_string() &&
                        ipv4->get_broadcast_address().to_string() <= relevant_ipv4->get_broadcast_address().to_string()
                    ) {
                        // cout << " => subnet ARP SCAN";
                        // subnet => run ARP *and* ICMP scan
                        shared_ptr<AbstractScanner> scanner;
                        scanner = static_pointer_cast<AbstractScanner>(make_shared<ARPScanner>(interface, arg_wait));
                        Utils::log_info("Starting ARP scan on interface " + interface->get_name() + " for IP range " + ipv4->get_network_address().to_string() + "-" + ipv4->get_broadcast_address().to_string());

                        scanners.push_back(make_pair(scanner, make_shared<thread>(&AbstractScanner::start, scanner)));
                        running_arp[interface_name] = true;
                    }

                    // cout << " => network ICMP scan";

                    // run ICMP scan
                    shared_ptr<AbstractScanner> scanner;
                    scanner = static_pointer_cast<AbstractScanner>(make_shared<ICMPScanner>(relevant_ipv4, arg_wait, interface));
                    Utils::log_info("Starting ICMP ping scan on interface " + interface->get_name() + " for IP range " + relevant_ipv4->get_network_address().to_string() + "-" + relevant_ipv4->get_broadcast_address().to_string());

                    scanners.push_back(make_pair(scanner, make_shared<thread>(&AbstractScanner::start, scanner)));
                }
                // cout << endl;
            }
        }

        show_progress();

        for(auto scanner : scanners) {
            scanner.second->join();
            auto scanner_result = scanner.first->get_hosts();
            live_hosts.insert(scanner_result.begin(), scanner_result.end());
        }
        cerr << "\033[1;36;1m[INFO] Finished scanning for live hosts. Found " << live_hosts.size() << " live hosts:\033[0m\n";

        if(interrupted) {
            print_hosts();
            return;
        }

        scanners.clear();

        // prepare ports to be scanned
        if (ports.size() == 0) {
            ports.resize(65536);
            iota(ports.begin(), ports.end(), 1);
        }

        mutex hosts_mtx;
        shared_ptr<Interface> interface = nullptr;
        if(interfaces.size() == 1) {
            interface = interfaces.front();
        }

        if(arg_tcp) {
            cerr << "\033[1;36;1m[INFO] Starting TCP PORT scan\033[0m\n";
            // start tcp scanner
            shared_ptr<AbstractScanner> scanner = static_pointer_cast<AbstractScanner>(make_shared<TCPScanner>(live_hosts, ports, &hosts_mtx, arg_wait, interface));
            scanners.push_back(make_pair(scanner, make_shared<thread>(&AbstractScanner::start, scanner)));
        }
        if (arg_udp) {
            cerr << "\033[1;36;1m[INFO] Starting UDP PORT scan\033[0m\n";
            // start udp scanner
            shared_ptr<AbstractScanner> scanner = static_pointer_cast<AbstractScanner>(make_shared<UDPScanner>(live_hosts, ports, &hosts_mtx, arg_wait, interface));
            scanners.push_back(make_pair(scanner, make_shared<thread>(&AbstractScanner::start, scanner)));
        }

        show_progress();

        // wait for them to join back
        for(auto scanner : scanners) {
            scanner.second->join();
            auto scanner_result = scanner.first->get_hosts();
            live_hosts.insert(scanner_result.begin(), scanner_result.end());
        }

        // PRINT OUT ALL HOSTS AND THEIR INFO
        print_hosts();
        return;
}

void print_help() {
    cout << "isamon [-h] [-i <interface>] [-t] [-u] [-p <port>] [-w <ms>] [-n <net_address/mask>]" << endl;
    cout << "\t-h --help -- zobrazí nápovědu" << endl;
    cout << "\t-i --interface <interface> -- rozhraní na kterém bude nástroj scanovat" << endl;
    cout << "\t-n --network <net_address/mask> -- ip adresa síťe s maskou definující rozsah pro scanování" << endl;
    cout << "\t-t --tcp -- použije TCP" << endl;
    cout << "\t-u --udp -- použije UDP" << endl;
    cout << "\t-p --port <port> -- specifikace scanovaného portu, pokud není zadaný, scanujte celý rozsah" << endl;
    cout << "\t-w --wait <ms> -- dodatečná informace pro Váš nástroj jaké je maximální přípustné RTT" << endl;
}

void show_progress() {
    uint8_t counter = 0;
    float percent = 0.0f;
    while (percent < 1) {
        unsigned long total = 0;
        unsigned long scanned = 0;
        for(auto scanner : scanners) {
            total += scanner.first->get_total();
            scanned += scanner.first->get_scanned();
        }
        if(total == 0) {
            if(++counter == 3) return;
            usleep(5*1000);
            continue;
        }
        percent = (float)scanned/(float)total;
        Utils::progress_bar(percent);
    }
    cout << endl << flush;
}

void print_hosts() {
    for (auto host : live_hosts) {
        host.second->print_info();
    }
}

void interrupt_handler(int type) {
    static int exit_counter = 0;
    if (type != SIGINT) {
        return;
    }

    exit_counter++;
    if(exit_counter == 3) {
        cerr << "ok, ok... calm down. exiting now" << endl;
        Utils::print_error(254);
    }
    for(auto scanner : scanners) {
        scanner.first->stop();
    }
    interrupted = true;
}
