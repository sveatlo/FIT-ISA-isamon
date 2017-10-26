#ifndef ABSTRACT_SCANNER_H
#define ABSTRACT_SCANNER_H

#include <map>
#include <string>
#include <memory>
#include "host.h"

using namespace std;

class AbstractScanner {
public:
    virtual void start() =0;
    virtual void stop() =0;
    virtual map<string, shared_ptr<Host>> get_hosts() =0;

protected:
    map<string, shared_ptr<Host>> hosts;
};

#endif
