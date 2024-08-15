#ifndef PCAPINTERPRETER_H
#define PCAPINTERPRETER_H

#include <string>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "IInterpreter.h"
#include "ConsoleHandler.h"


struct PcapFile
{
    std::string srcIp;
    std::string dstIp;
    uint8_t protocol_number;
    std::string protocol_name;
    std::size_t length;
    std::vector<unsigned char> data;
};

class PcapInterpreter : public IInterpreter<void>
{
public:
    PcapInterpreter();
    virtual ~PcapInterpreter() = default;
    void setFilter(const std::string& srcIp, const std::string& dstIp);
    bool isMatchedFilter(const std::string& srcIp, const std::string& dstIp) const;
    void interpret(const unsigned char* packet, std::size_t length) override;
    std::string getProtocolName(int protocol_number);


private:
    std::string m_FilterSrcIp;
    std::string m_FilterDstIp;
    std::unordered_map<int, std::string> ipProtocolNumbers;
};

#endif // PCAPINTERPRETER_H
