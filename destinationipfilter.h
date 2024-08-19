#ifndef DESTINATIONIPFILTER_H
#define DESTINATIONIPFILTER_H

#include "IPacketFilter.h"

class DestinationIpFilter : public PacketFilter
{
public:
    explicit DestinationIpFilter(const std::string& dstIp) : dstIp(dstIp) {}

    bool matches(const PcapFile& packet) const override
    {
        return packet.dstIp == dstIp;
    }

private:
    std::string dstIp;
};


#endif // DESTINATIONIPFILTER_H
