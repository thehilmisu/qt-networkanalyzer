#ifndef IPACKETFILTER_H
#define IPACKETFILTER_H

#include "pcapfile.h"

class PacketFilter
{
public:
    virtual ~PacketFilter() = default;

    virtual bool matches(const PcapFile& packet) const = 0;
};


#endif // IPACKETFILTER_H
