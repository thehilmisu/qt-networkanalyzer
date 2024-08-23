#ifndef PROTOCOLNUMBERS_H
#define PROTOCOLNUMBERS_H

#include <unordered_map>
#include <string>

class IPProtocolNumbers 
{
public:
    // Static method to get the protocol name by number
    static std::string getProtocolName(int protocolNumber);

private:
    // The map that holds the protocol numbers and their corresponding names
    static const std::unordered_map<int, std::string> ipProtocolNumbers;
};

#endif // PROTOCOLNUMBERS_H
