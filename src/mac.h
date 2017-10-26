#ifndef MAC_H
#define MAC_H

#include <bitset>
#include <string>
#include "definitions.h"

using namespace std;

class MAC {
public:
    MAC(bitset<MAC_BITLENGTH>);
    MAC(unsigned char mac[MAC_LENGTH]);

    bitset<MAC_BITLENGTH> value();
    string to_string();
private:
    bitset<MAC_BITLENGTH> address;
    string address_string;
};

#endif
