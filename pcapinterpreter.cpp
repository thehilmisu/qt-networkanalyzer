#include "pcapinterpreter.h"


PcapInterpreter::PcapInterpreter() : m_FilterSrcIp(""), m_FilterDstIp("")
{
    // got it from wikipedia not a complete list
    ipProtocolNumbers =
        {
            {0, "HOPOPT"},       // IPv6 Hop-by-Hop Option
            {1, "ICMP"},         // Internet Control Message Protocol
            {2, "IGMP"},         // Internet Group Management Protocol
            {3, "GGP"},          // Gateway-to-Gateway Protocol
            {4, "IP-in-IP"},     // IP in IP (encapsulation)
            {5, "ST"},           // Stream Protocol
            {6, "TCP"},          // Transmission Control Protocol
            {8, "EGP"},          // Exterior Gateway Protocol
            {9, "IGP"},          // Interior Gateway Protocol
            {17, "UDP"},         // User Datagram Protocol
            {27, "RDP"},         // Reliable Datagram Protocol
            {41, "IPv6"},        // IPv6 encapsulation
            {43, "IPv6-Route"},  // Routing Header for IPv6
            {44, "IPv6-Frag"},   // Fragment Header for IPv6
            {47, "GRE"},         // Generic Routing Encapsulation
            {50, "ESP"},         // Encap Security Payload
            {51, "AH"},          // Authentication Header
            {58, "ICMPv6"},      // ICMP for IPv6
            {59, "IPv6-NoNxt"},  // No Next Header for IPv6
            {60, "IPv6-Opts"},   // Destination Options for IPv6
            {88, "EIGRP"},       // EIGRP
            {89, "OSPF"},        // Open Shortest Path First
            {94, "IPIP"},        // IP-within-IP Encapsulation Protocol
            {97, "ETHERIP"},     // Ethernet-within-IP Encapsulation
            {112, "VRRP"},       // Virtual Router Redundancy Protocol
            {115, "L2TP"},       // Layer Two Tunneling Protocol
            {132, "SCTP"},       // Stream Control Transmission Protocol
            {136, "UDPLite"},    // Lightweight User Datagram Protocol
            {137, "MPLS-in-IP"}  // MPLS-in-IP
        };
}


void PcapInterpreter::setFilter(const std::string& srcIp, const std::string& dstIp)
{
    m_FilterSrcIp = srcIp;
    m_FilterDstIp = dstIp;
}

bool PcapInterpreter::isMatchedFilter(const std::string& srcIp, const std::string& dstIp) const
{
    bool srcMatch = m_FilterSrcIp.empty() || m_FilterSrcIp == srcIp;
    bool dstMatch = m_FilterDstIp.empty() || m_FilterDstIp == dstIp;
    return srcMatch && dstMatch;
}

std::string PcapInterpreter::getProtocolName(int protocol_number)
{
    auto it = ipProtocolNumbers.find(protocol_number);
    if (it != ipProtocolNumbers.end())
        return it->second;

    return "Unknown Protocol";
}

void PcapInterpreter::interpret(const unsigned char* packet, std::size_t length)
{
    PcapFile pFile;
    const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packet);

    // Extract source and destination IP addresses
    pFile.srcIp = inet_ntoa(ipHeader->ip_src);
    pFile.dstIp = inet_ntoa(ipHeader->ip_dst);

    // Extract protocol
    pFile.protocol_number = ipHeader->ip_p;

    // Extract protocol name
    pFile.protocol_name = getProtocolName(ipHeader->ip_p);

    // Extract total length
    pFile.length = ntohs(ipHeader->ip_len);

    // Extract data (payload)
    const unsigned char* dataStart = packet + (ipHeader->ip_hl * 4);
    std::size_t dataLength = length - (ipHeader->ip_hl * 4);
    pFile.data.assign(dataStart, dataStart + dataLength);

    bool isMatch = isMatchedFilter(m_FilterSrcIp, m_FilterDstIp);

    //Application::getInstance().addPackets(pFile);

    ConsoleHandler::getInstance().print(pFile.dstIp);
}

