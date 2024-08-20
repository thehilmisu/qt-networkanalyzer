#ifndef PCAPINTERPRETER_H
#define PCAPINTERPRETER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "IInterpreter.h"
//#include "ConsoleHandler.h"
#include "pcapfile.h"
#include <QObject>
#include <QDebug>



class PcapInterpreter :  public QObject, public IInterpreter<void>
{
    Q_OBJECT

public:
    explicit PcapInterpreter(QObject *parent = nullptr);
    virtual ~PcapInterpreter() = default;
    void setFilter(const std::string& srcIp, const std::string& dstIp);
    bool isMatchedFilter(const std::string& srcIp, const std::string& dstIp) const;
    void interpret(const unsigned char* packet, std::size_t length) override;
    std::string getProtocolName(int protocol_number);
    QVector<PacketLineData> getPacketLineData(const std::vector<unsigned char>& data);

signals:
    void packetConstructed(const PcapFile &pFile);

private:
    std::string m_FilterSrcIp;
    std::string m_FilterDstIp;
    std::unordered_map<int, std::string> ipProtocolNumbers;
    QString formatPacketData(const std::vector<unsigned char>& data);
    QString formatPacketDataContinuation(const std::vector<unsigned char>& data);
    bool isWordContinuation(const std::string& prevLine, const std::string& currentLine);
    QString detectLinksAndAPICalls(const std::vector<unsigned char>& data);


};

#endif // PCAPINTERPRETER_H
