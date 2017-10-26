#include <sstream>
#include "utils.h"
#include "ipv4.h"

IPv4::IPv4(unsigned char* _address, unsigned char* _netmask) {
    this->address = (unsigned char)_address[0] << 24 | (unsigned char)_address[1] << 16 | (unsigned char)_address[2] << 8 | (unsigned char)_address[3];
    if (_netmask != nullptr) {
        this->netmask = (unsigned char)_netmask[0] << 24 | (unsigned char)_netmask[1] << 16 | (unsigned char)_netmask[2] << 8 | (unsigned char)_netmask[3];
    }

    this->generate_strings();
}

IPv4::IPv4(bitset<IPV4_BITLENGTH> _address, bitset<IPV4_BITLENGTH> _netmask) {
    this->address = _address;
    this->netmask = _netmask;

    this->generate_strings();
}

void IPv4::generate_strings() {
    stringstream address_ss;
    address_ss << (this->address >> 24).to_ulong() << "." << (Utils::rotr(this->address, 24) >> 24).to_ulong() << "." << (Utils::rotr(this->address, 16) >> 24).to_ulong() << "." << (Utils::rotr(this->address, 8) >> 24).to_ulong();
    stringstream netmask_ss;
    netmask_ss << (this->netmask >> 24).to_ulong() << "." << (Utils::rotr(this->netmask, 24) >> 24).to_ulong() << "." << (Utils::rotr(this->netmask, 16) >> 24).to_ulong() << "." << (Utils::rotr(this->netmask, 8) >> 24).to_ulong();

    this->address_string = address_ss.str();
    this->netmask_string = netmask_ss.str();
}


bitset<IPV4_BITLENGTH> IPv4::get_address() {
    return this->address;
}

bitset<IPV4_BITLENGTH> IPv4::get_netmask() {
    return this->netmask;
}

bitset<IPV4_BITLENGTH> IPv4::get_network_address() {
    return this->address & this->netmask;
}

bitset<IPV4_BITLENGTH> IPv4::get_broadcast_address() {
    return this->address | ~this->netmask;
}

string IPv4::get_network_address_string() {
    bitset<IPV4_BITLENGTH> address = this->get_network_address();
    stringstream ss;
    ss << (address >> 24).to_ulong() << "." << (Utils::rotr(address, 24) >> 24).to_ulong() << "." << (Utils::rotr(address, 16) >> 24).to_ulong() << "." << (Utils::rotr(address, 8) >> 24).to_ulong();
    return ss.str();
}

string IPv4::get_broadcast_address_string() {
    bitset<IPV4_BITLENGTH> address = this->get_broadcast_address();
    stringstream ss;
    ss << (address >> 24).to_ulong() << "." << (Utils::rotr(address, 24) >> 24).to_ulong() << "." << (Utils::rotr(address, 16) >> 24).to_ulong() << "." << (Utils::rotr(address, 8) >> 24).to_ulong();
    return ss.str();
}

string IPv4::get_address_string() {
    return this->address_string;
}
string IPv4::get_netmask_string() {
    return this->netmask_string;
}

uint32_t IPv4::to_uint32() {
    return this->address.to_ulong();
}
