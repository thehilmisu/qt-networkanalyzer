#ifndef PACKETFILTERMANAGER_H
#define PACKETFILTERMANAGER_H

#include "IPacketFilter.h"
#include <QList>
#include <QSharedPointer>

class PacketFilterManager {
public:
    void addFilter(QSharedPointer<PacketFilter> filter)
    {
        filters.append(filter);
    }

    QVector<PcapFile> applyFilters(const QVector<PcapFile>& packets) const
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

    void clearFilters()
    {
        filters.clear();
    }

private:
    bool matchesAllFilters(const PcapFile& packet) const
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

    QList<QSharedPointer<PacketFilter>> filters;  // Use QSharedPointer instead of std::unique_ptr
};


#endif // PACKETFILTERMANAGER_H
