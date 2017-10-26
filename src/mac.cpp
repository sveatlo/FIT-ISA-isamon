#include <sstream>
#include "mac.h"
#include "utils.h"

MAC::MAC(unsigned char _address[MAC_LENGTH]) {
    unsigned long umac = (unsigned long)_address[0] << 40 |
                    (unsigned long)_address[1] << 32 |
                    (unsigned long)_address[2] << 24 |
                    (unsigned long)_address[3] << 16 |
                    (unsigned long)_address[4] << 8 |
                    (unsigned long)_address[5];
    this->address = bitset<MAC_BITLENGTH>(umac);

    // create and save string
    char mac_cstring[MAC_LENGTH*2+5];
    int len = 0;
    for(int i = 0; i < MAC_LENGTH; i++) {
        len += sprintf(mac_cstring+len, "%02X%s",_address[i],i < 5 ? ":":"");
    }
    this->address_string = string(mac_cstring);
}

MAC::MAC(bitset<MAC_BITLENGTH> _address) {
    this->address = _address;

    stringstream mac;
    mac << uppercase << hex;
    for(size_t n = 0; n < MAC_LENGTH; n++) {
        mac << ((this->address << n*8) >> 40).to_ulong();
        if (n < MAC_LENGTH - 1) {
            mac << ":";
        }
    }
    this->address_string = mac.str();
}

bitset<MAC_BITLENGTH> MAC::value() {
    return this->address;
}

string MAC::to_string() {
    return this->address_string;
}
