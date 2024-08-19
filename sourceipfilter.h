#ifndef SOURCEIPFILTER_H
#define SOURCEIPFILTER_H

#include "IPacketFilter.h"

class SourceIpFilter : public PacketFilter
{
public:
    explicit SourceIpFilter(const std::string& srcIp) : srcIp(srcIp) {}

    bool matches(const PcapFile& packet) const override
    {
        return packet.srcIp == srcIp;
    }

private:
    std::string srcIp;
};


#endif // SOURCEIPFILTER_H
