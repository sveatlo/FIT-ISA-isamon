#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sstream>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "utils.h"
#include "definitions.h"

using namespace std;

void Utils::log_info(string msg, string end) {
    cerr << "\033[1;36;1m[INFO] " << msg << "\033[0m" << end;
}

void Utils::log_warn(string msg, string end) {
    cerr << "\033[1;33m[WARN] " << msg << "\033[0m" << end;
}

void Utils::log_error(string msg, string end) {
    cerr << "\033[1;31m[EROR] " << msg << "\033[0m" << end;
}


void Utils::print_error(int code, string error_string) {
    map<int, string> error_strings = {
            {1, "Invalid arguments"},
            {101, "Interface error"},
            {102, "Socket bind error"},
            {103, "ARP scanning error"},
            {104, "ARP receiving error"},
            {105, "ICMP scanning error"},
            {106, "ICMP receiving error"},
            {107, "TCP scanning error"},
            {108, "TCP receiving error"},
            {109, "UDP scanning error"},
            {110, "UDP receiving error"},
            {150, "Cannot get MAC address for interface"},
            {254, "Excessive use of Ctrl+c"},
            {255, "Run isamon as root, stupid!"}
    };

    cerr << "\033[1;31m[EROR] " << (error_strings.count(code) > 0 ? error_strings[code] : "Unknown error") << ".\033[0m ";
    if (error_string != "") {
        cerr << "\033[1;31m" << error_string << "\033[0m\n";
    } else if(errno != 0 && code != 255) {
        cerr << "\033[1;31m" << strerror(errno) << "\033[0m\n";
    } else {
        cerr << endl;
    }
    exit(code);
}

uint32_t Utils::ip_to_int(const string ip) {
    int a, b, c, d;
    uint32_t addr = 0;

    if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        throw 1;
    }

    addr = a << 24;
    addr |= b << 16;
    addr |= c << 8;
    addr |= d;
    return addr;
}

string Utils::int_to_ip(const uint32_t addr) {
    stringstream ss;
    ss << (addr >> 24) << "." << (Utils::rotr(addr, 24) >> 24) << "." << (Utils::rotr(addr, 16) >> 24) << "." << (Utils::rotr(addr, 8) >> 24);
    return ss.str();
}

unsigned int Utils::rotr(const unsigned int value, int shift) {
    if ((shift &= sizeof(value)*8 - 1) == 0)
      return value;
    return (value >> shift) | (value << (sizeof(value)*8 - shift));
}

unsigned int Utils::rotl(const unsigned int value, int shift) {
    if ((shift &= sizeof(value)*8 - 1) == 0)
      return value;
    return (value << shift) | (value >> (sizeof(value)*8 - shift));
}

// Computing the internet checksum (RFC 1071).
uint16_t Utils::checksum(uint16_t *addr, int len) {
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

/**
 * Get local IP
 * Copyright https://github.com/jiecchen https://github.com/jiecchen/portScanner/blob/master/test.c
 *
 * @param buf return param
 */
void Utils::get_local_ip(char* buf) {
    int sock = socket ( AF_INET, SOCK_DGRAM, 0);

    const char* kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;

    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons( dns_port );

    if (connect(sock , (const struct sockaddr*)&serv, sizeof(serv)) < 0) {
        Utils::print_error(104);
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(sock, (struct sockaddr*) &name, &namelen);

    inet_ntop(AF_INET, &name.sin_addr, buf, 100);

    close(sock);
}


/**
 * Prints out progressbar to stderr
 * Copyright leemes https://stackoverflow.com/a/14539953/1419318
 *
 * @param progress progress in %
 */
void Utils::progress_bar(float progress) {
    int barWidth = 70;

    string bar = "[";
    int pos = barWidth * progress;
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) {
            bar += "=";
        } else if (i == pos) {
            bar += ">";
        } else {
            bar += " ";
        }
    }
    bar += "] ";
    bar += to_string(int(progress * 100.0));
    bar += " \%\r";
    cerr << bar;
    cerr.flush();
}
