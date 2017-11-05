#ifndef ABSTRACT_SCANNER_H
#define ABSTRACT_SCANNER_H

#include <map>
#include <string>
#include <memory>
#include "host.h"

using namespace std;

/**
 * Abstract class which describe any scanner using virtual methods
 */
class AbstractScanner {
public:
    /**
     * Starts a new scan
     */
    virtual void start() =0;

    /**
     * Stops an ongoing scan
     */
    virtual void stop() =0;

    /**
     * Return the hosts from private propertt hosts
     */
    map<string, shared_ptr<Host>> get_hosts() {
        return this->hosts;
    }

    /**
     * Get the number of all entities which are scheduled to be scanned
     * @return number of all entities which are scheduled to be scanned
     */
    int get_total() {
        return this->total;
    }

    /**
     * Get the number of entities already scanned
     * @return number of scanned entties
     */
    int get_scanned() {
        return this->scanned;
    }

protected:
    /**
     * Hosts, that were found during scan or
     * hosts to scan
     */
    map<string, shared_ptr<Host>> hosts;

    /**
     * Marks the end of scan
     */
    bool keep_scanning = true;

    /**
     * Time in ms to wait for responses
     */
    int wait = 1000;

    /**
     * FD to use to send sockets
     */
    int snd_sd;

    /**
     * FD to use to receive sockets
     */
    int rcv_sd;

    /**
     * Total number of entities to scan
     */
    unsigned long total = 0;

    /**
     * Number of entities scanned
     */
    unsigned long scanned = 0;

    /**
     * Run all the preparation work before sending or receiving anything
     */
    virtual void prepare() =0;

    /**
     * Creates sockets to receive and send data
     */
    virtual void bind_sockets() =0;
};

#endif
