#include  <iostream>
#include <unistd.h>
#include "abstract_scanner.h"

AbstractScanner::~AbstractScanner() {
    close(this->snd_sd);
    close(this->rcv_sd);
}

map<string, shared_ptr<Host>> AbstractScanner::get_hosts() {
    return this->hosts;
}

int AbstractScanner::get_total() {
    return this->total;
}

int AbstractScanner::get_scanned() {
    return this->scanned;
}
