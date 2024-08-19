#ifndef PROTOCOLFILTER_H
#define PROTOCOLFILTER_H

#include "IPacketFilter.h"

class ProtocolFilter : public PacketFilter
{
public:
    explicit ProtocolFilter(const std::string& protocolName) : protocolName(protocolName) {}

    bool matches(const PcapFile& packet) const override
    {
        return packet.protocol_name == protocolName;
    }

private:
    std::string protocolName;
};


#endif // PROTOCOLFILTER_H
