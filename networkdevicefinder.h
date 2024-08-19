#ifndef NETWORK_DEVICE_FINDER_H
#define NETWORK_DEVICE_FINDER_H

#include <vector>
#include <string>

#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#elif defined(__APPLE__) || defined(__MACH__)
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h> // Ensure this is included for getnameinfo and NI constants
#else
#include <ifaddrs.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

class NetworkDeviceFinder
{
public:
    NetworkDeviceFinder(const NetworkDeviceFinder&) = delete;
    NetworkDeviceFinder& operator=(const NetworkDeviceFinder&) = delete;
    static NetworkDeviceFinder& getInstance();
    std::string chooseDevice();
    std::vector<std::string> listDevices();

private:
    NetworkDeviceFinder();
    ~NetworkDeviceFinder();

};

#endif // NETWORK_DEVICE_FINDER_H
