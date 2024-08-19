#ifndef PCAPFILE_H
#define PCAPFILE_H

#include <QObject>

struct PcapFile
{
    std::string srcIp;
    std::string dstIp;
    uint8_t protocol_number;
    std::string protocol_name;
    std::size_t length;
    std::vector<unsigned char> data;
    QString formattedData;
};

#endif // PCAPFILE_H
