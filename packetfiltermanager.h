#ifndef PACKETFILTERMANAGER_H
#define PACKETFILTERMANAGER_H

#include "IPacketFilter.h"
#include <QList>
#include <QSharedPointer>

class PacketFilterManager 
{
public:
    void addFilter(QSharedPointer<PacketFilter> filter);
    QVector<PcapFile> applyFilters(const QVector<PcapFile>& packets) const;
    void clearFilters();

private:
    bool matchesAllFilters(const PcapFile& packet) const;
    QList<QSharedPointer<PacketFilter>> filters;  // Use QSharedPointer instead of std::unique_ptr
};


#endif // PACKETFILTERMANAGER_H
