#include "pcapinterpreter.h"
#include <iomanip>
#include <iostream>
#include <regex>
#include <set>


PcapInterpreter::PcapInterpreter(QObject *parent)
    : QObject(parent)
{

    // Register the PcapFile type with Qt's meta-object system
    qRegisterMetaType<PcapFile>("PcapFile");

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

QString PcapInterpreter::formatPacketData(const std::vector<unsigned char>& data)
{
    const int bytesPerLine = 16;  // Number of bytes to display per line
    QString formattedData;
    std::ostringstream oss;

    for (std::size_t i = 0; i < data.size(); i += bytesPerLine)
    {
        // Print the offset in the packet
        oss << std::setw(6) << std::setfill('0') << std::hex << i << ": ";

        // Print hex values
        for (std::size_t j = 0; j < bytesPerLine; ++j)
        {
            if (i + j < data.size())
            {
                oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i + j]) << " ";
            }
            else
            {
                oss << "   ";  // Add spacing for incomplete lines
            }
        }

        oss << "  ";

        // Print ASCII representation
        for (std::size_t j = 0; j < bytesPerLine; ++j)
        {
            if (i + j < data.size())
            {
                unsigned char byte = data[i + j];
                if (std::isprint(byte))
                {
                    oss << byte;
                }
                else
                {
                    oss << '.';
                }
            }
        }

        oss << "\n";
    }

    formattedData = QString::fromStdString(oss.str());
    return formattedData;
}

QVector<PacketLineData> PcapInterpreter::getPacketLineData(const std::vector<unsigned char>& data)
{
    QVector<PacketLineData> packetLines;
    const int bytesPerLine = 16;  // Number of bytes to display per line
    std::string previousAscii;    // Store the previous ASCII part to detect continuation

    for (std::size_t i = 0; i < data.size(); i += bytesPerLine) {
        PacketLineData lineData;

        // Set the offset
        std::ostringstream offsetStream;
        offsetStream << std::setw(6) << std::setfill('0') << std::hex << i;
        lineData.offset = offsetStream.str() + " ";

        std::string hexPart;
        std::string asciiPart;
        bool likelyContinuation = false;  // Flag to determine if this line should be combined with the previous

        // Accumulate hex values and ASCII characters
        for (std::size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < data.size()) {
                unsigned char byte = data[i + j];
                hexPart += QString("%1 ").arg(byte, 2, 16, QLatin1Char('0')).toStdString();
                if (std::isprint(byte)) {
                    asciiPart += byte;
                } else {
                    asciiPart += '.';
                }
            } else {
                hexPart += "   ";  // Add spacing for incomplete lines
            }
        }

        // Contextual analysis to determine if the current line is a continuation of the previous
        if (!previousAscii.empty()) {
            if (std::isprint(previousAscii.back()) && std::isprint(asciiPart[0])) {
                likelyContinuation = true;
            }

            if (std::isalnum(previousAscii.back()) && std::isalnum(asciiPart[0])) {
                likelyContinuation = true;
            }

            if (isWordContinuation(previousAscii, asciiPart)) {
                likelyContinuation = true;
            }
        }

        // If likely a continuation, combine the previous line with the current one
        if (likelyContinuation) {
            previousAscii += asciiPart;
            lineData.hexPart = hexPart;
            lineData.asciiPart = previousAscii;
            previousAscii.clear();  // Clear the buffer after combining
        } else {
            if (!previousAscii.empty()) {
                PacketLineData previousLineData;
                previousLineData.offset = lineData.offset;
                previousLineData.hexPart = hexPart;
                previousLineData.asciiPart = previousAscii;
                packetLines.push_back(previousLineData);
            }
            previousAscii = asciiPart;
        }

        lineData.hexPart = hexPart;
        lineData.asciiPart = asciiPart;
        packetLines.push_back(lineData);
    }

    // Add any remaining buffered ASCII part
    if (!previousAscii.empty()) {
        PacketLineData finalLineData;
        std::ostringstream finalOffsetStream;
        finalOffsetStream << std::setw(6) << std::setfill('0') << std::hex << data.size();
        finalLineData.offset = finalOffsetStream.str() + " ";
        finalLineData.hexPart = "";  // No additional hex data to add
        finalLineData.asciiPart = previousAscii;
        packetLines.push_back(finalLineData);
    }

    return packetLines;
}

QString PcapInterpreter::formatPacketDataContinuation(const std::vector<unsigned char>& data) {
    QString formattedData;
    std::ostringstream oss;

    const int bytesPerLine = 16;  // Number of bytes to display per line
    std::string previousAscii;    // Store the previous ASCII part to detect continuation

    for (std::size_t i = 0; i < data.size(); i += bytesPerLine) {
        // Print the offset in the packet
        oss << std::setw(6) << std::setfill('0') << std::hex << i << ": ";

        std::string hexPart;
        std::string asciiPart;

        bool likelyContinuation = false;  // Flag to determine if this line should be combined with the previous

        // Accumulate hex values and ASCII characters
        for (std::size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < data.size()) {
                unsigned char byte = data[i + j];
                hexPart += QString("%1 ").arg(byte, 2, 16, QLatin1Char('0')).toStdString();
                if (std::isprint(byte)) {
                    asciiPart += byte;
                } else {
                    asciiPart += '.';
                }
            } else {
                hexPart += "   ";  // Add spacing for incomplete lines
            }
        }

        // Contextual analysis to determine if the current line is a continuation of the previous
        if (!previousAscii.empty()) {
            // Heuristic: Check if the last character of the previous line and the first character of this line are printable
            if (std::isprint(previousAscii.back()) && std::isprint(asciiPart[0])) {
                likelyContinuation = true;
            }

            // Additional heuristic: Check if the ASCII part looks like a continuation of a string
            if (std::isalnum(previousAscii.back()) && std::isalnum(asciiPart[0])) {
                likelyContinuation = true;
            }

            // Check for known patterns (e.g., words being split across lines)
            if (isWordContinuation(previousAscii, asciiPart)) {
                likelyContinuation = true;
            }
        }

        // If likely a continuation, combine the previous line with the current one
        if (likelyContinuation) {
            previousAscii += asciiPart;
            oss << "  " << previousAscii << "\n";
            previousAscii.clear();  // Clear the buffer after combining
        } else {
            if (!previousAscii.empty()) {
                // Print the previous buffered line if it's not combined
                oss << "  " << previousAscii << "\n";
            }
            previousAscii = asciiPart;
        }
    }

    // Print any remaining buffered ASCII part
    if (!previousAscii.empty()) {
        oss << "  " << previousAscii << "\n";
    }

    formattedData = QString::fromStdString(oss.str());
    return formattedData;
}

// Heuristic function to determine if two lines represent a continuation of a word
bool PcapInterpreter::isWordContinuation(const std::string& prevLine, const std::string& currentLine) {
    // Check if the previous line ends with a non-space and the current line starts with a non-space
    if (!prevLine.empty() && std::isalnum(prevLine.back()) && std::isalnum(currentLine[0])) {
        return true;
    }
    // Additional checks can be added here for specific patterns
    return false;
}


QString PcapInterpreter::detectLinksAndAPICalls(const std::vector<unsigned char>& data) {
    QString detectedLinks;
    std::string payload(data.begin(), data.end());

    std::string combinedFragment;
    std::string lastFragment;

    // Set of valid TLDs (this is a small sample, you can expand it as needed)
    std::set<std::string> validTLDs = {
        "com", "org", "net", "edu", "gov", "io", "co",
        "nl", "de", "fr", "uk", "ca", "au", "us", "cn", "jp"
    };

    // Regex to match a valid URL with a known TLD
    std::regex urlRegex(R"([a-z0-9][-a-z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)");
    std::smatch urlMatch;

    for (size_t i = 0; i < payload.size(); ++i) {
        if (std::isprint(payload[i])) {
            combinedFragment += payload[i];
        } else if (!combinedFragment.empty()) {
            // Process the fragment for potential URLs
            if (std::regex_search(combinedFragment, urlMatch, urlRegex)) {
                std::string detectedUrl = urlMatch.str();
                size_t dotPos = detectedUrl.rfind('.');
                if (dotPos != std::string::npos) {
                    std::string tld = detectedUrl.substr(dotPos + 1);
                    std::string prefix = detectedUrl.substr(0, dotPos);

                    // Check if TLD is valid and prefix is all lowercase
                    if (validTLDs.find(tld) != validTLDs.end() && std::all_of(prefix.begin(), prefix.end(), [](unsigned char c) { return std::islower(c) || std::isdigit(c) || c == '-' || c == '.'; })) {
                        detectedLinks += "URL Detected: " + QString::fromStdString(detectedUrl) + "\n";
                    }
                }
            } else if (!lastFragment.empty()) {
                // Attempt to combine with the last fragment
                std::string potentialUrl = lastFragment + combinedFragment;
                if (std::regex_search(potentialUrl, urlMatch, urlRegex)) {
                    std::string detectedUrl = urlMatch.str();
                    size_t dotPos = detectedUrl.rfind('.');
                    if (dotPos != std::string::npos) {
                        std::string tld = detectedUrl.substr(dotPos + 1);
                        std::string prefix = detectedUrl.substr(0, dotPos);

                        // Check if TLD is valid and prefix is all lowercase
                        if (validTLDs.find(tld) != validTLDs.end() && std::all_of(prefix.begin(), prefix.end(), [](unsigned char c) { return std::islower(c) || std::isdigit(c) || c == '-' || c == '.'; })) {
                            detectedLinks += "URL Detected (From Combined Fragments): " + QString::fromStdString(detectedUrl) + "\n";
                        }
                    }
                }
            }

            // Attempt to detect if the current fragment is part of a domain chain like "microsoft.com"
            if (lastFragment.size() > 0 && combinedFragment.find('.') != std::string::npos) {
                // Combine lastFragment and combinedFragment considering they might form a URL across fragments
                std::string potentialCombined = lastFragment + combinedFragment;
                if (std::regex_search(potentialCombined, urlMatch, urlRegex)) {
                    std::string detectedUrl = urlMatch.str();
                    size_t dotPos = detectedUrl.rfind('.');
                    if (dotPos != std::string::npos) {
                        std::string tld = detectedUrl.substr(dotPos + 1);
                        std::string prefix = detectedUrl.substr(0, dotPos);

                        // Check if TLD is valid and prefix is all lowercase
                        if (validTLDs.find(tld) != validTLDs.end() && std::all_of(prefix.begin(), prefix.end(), [](unsigned char c) { return std::islower(c) || std::isdigit(c) || c == '-' || c == '.'; })) {
                            detectedLinks += "URL Detected (Across Fragments): " + QString::fromStdString(detectedUrl) + "\n";
                        }
                    }
                }
            }

            lastFragment = combinedFragment;
            combinedFragment.clear();
        }
    }

    // Final check for any remaining fragment at the end of the data
    if (!combinedFragment.empty()) {
        if (std::regex_search(combinedFragment, urlMatch, urlRegex)) {
            std::string detectedUrl = urlMatch.str();
            size_t dotPos = detectedUrl.rfind('.');
            if (dotPos != std::string::npos) {
                std::string tld = detectedUrl.substr(dotPos + 1);
                std::string prefix = detectedUrl.substr(0, dotPos);

                // Check if TLD is valid and prefix is all lowercase
                if (validTLDs.find(tld) != validTLDs.end() && std::all_of(prefix.begin(), prefix.end(), [](unsigned char c) { return std::islower(c) || std::isdigit(c) || c == '-' || c == '.'; })) {
                    detectedLinks += "URL Detected: " + QString::fromStdString(detectedUrl) + "\n";
                }
            }
        } else if (!lastFragment.empty()) {
            std::string potentialUrl = lastFragment + combinedFragment;
            if (std::regex_search(potentialUrl, urlMatch, urlRegex)) {
                std::string detectedUrl = urlMatch.str();
                size_t dotPos = detectedUrl.rfind('.');
                if (dotPos != std::string::npos) {
                    std::string tld = detectedUrl.substr(dotPos + 1);
                    std::string prefix = detectedUrl.substr(0, dotPos);

                    // Check if TLD is valid and prefix is all lowercase
                    if (validTLDs.find(tld) != validTLDs.end() && std::all_of(prefix.begin(), prefix.end(), [](unsigned char c) { return std::islower(c) || std::isdigit(c) || c == '-' || c == '.'; })) {
                        detectedLinks += "URL Detected (From Combined Fragments): " + QString::fromStdString(detectedUrl) + "\n";
                    }
                }
            }
        }
    }

    return detectedLinks;
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

    pFile.formattedData = formatPacketDataContinuation(pFile.data);

    pFile.detectedLinks = detectLinksAndAPICalls(pFile.data);

    pFile.packetLineData = getPacketLineData(pFile.data);

    //bool isMatch = isMatchedFilter(m_FilterSrcIp, m_FilterDstIp);

    emit packetConstructed(pFile);

    //ConsoleHandler::getInstance().print(pFile.dstIp);
}

