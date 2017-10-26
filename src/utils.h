#ifndef UTILS_H
#define UTILS_H

#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <bitset>
#include <string>

using namespace std;

class Utils {
public:
    static void print_error(int code, string error_string = "");
    static uint32_t ip_to_int(const string ip);
    static string int_to_ip(const uint32_t addr);
    static uint16_t checksum(uint16_t *addr, int len);
    static void get_local_ip(char* buf);
    static void progress_bar(float progress);
    static unsigned int rotr(const unsigned int value, int shift);
    template <size_t N> static bitset<N> rotr(bitset<N> value, unsigned shift) {
        return value >> shift | value << (N-shift);
    }
    static unsigned int rotl(const unsigned int value, int shift);
    template <size_t N> static bitset<N> rotl(bitset<N> value, unsigned shift) {
        return value << shift | value >> (N-shift);
    }
    template <size_t N> static bitset<N> increment(bitset<N> val) {
        for (size_t i = 0; i < N; ++i) {
            if (val[i] == 0) {  // There will be no carry
                val[i] = 1;
                break;
            }
            val[i] = 0;  // This entry was 1; set to zero and carry the 1
        }
        return val;
    }
    template<size_t R, size_t L, size_t N> static bitset<N> subbitset(bitset<N> b) {
        static_assert(R <= L && L <= N, "invalid bitrange");
        b >>= R;
        b <<= (N - L + R);
        b >>= (N - L);
        return b;
    }
};

template<size_t N>
bool operator<(const bitset<N>& x, const bitset<N>& y)
{
    for (int i = N-1; i >= 0; i--) {
        if (x[i] ^ y[i]) return y[i];
    }
    return false;
}

// for TCP/UDP checksum calculation
struct pseudo_header {
    unsigned int saddr;
    unsigned int daddr;
    unsigned char placeholder;
    unsigned char proto;
    unsigned short len;

    struct tcphdr tcp;
};

#endif
