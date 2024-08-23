#include "packetfiltermanager.h"

void PacketFilterManager::addFilter(QSharedPointer<PacketFilter> filter)
{
    filters.append(filter);
}

QVector<PcapFile> PacketFilterManager::applyFilters(const QVector<PcapFile>& packets) const
{
    QVector<PcapFile> filteredPackets;
    for (const auto& packet : packets)
    {
        if (matchesAllFilters(packet))
        {
            filteredPackets.append(packet);
        }
    }
    return filteredPackets;
}

void PacketFilterManager::clearFilters()
{
    filters.clear();
}

bool PacketFilterManager::matchesAllFilters(const PcapFile& packet) const
{
    for (const auto& filter : filters)
    {
        if (!filter->matches(packet))
        {
            return false;
        }
    }
    return true;
}