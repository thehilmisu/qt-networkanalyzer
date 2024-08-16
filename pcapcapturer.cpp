#include "pcapcapturer.h"
#include "logger.h"
#include <iostream>

PcapCapturer& PcapCapturer::getInstance()
{
    static PcapCapturer instance;
    return instance;
}

PcapCapturer::~PcapCapturer()
{
    requestStop();
    quit();
    wait();  // Ensure the thread finishes
    if (handle)
    {
        pcap_close(handle);  // Cleanup pcap handle if still open
    }
}

void PcapCapturer::setDev(const std::string& dev)
{
    QMutexLocker locker(&mutex);
    device = dev.c_str();
    stopRequested = false;
}

void PcapCapturer::requestStop()
{
    QMutexLocker locker(&mutex);
    stopRequested = true;
    if (handle)
    {
        pcap_breakloop(handle);  // Break out of pcap_loop()
    }
}

void PcapCapturer::packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    Logger::getInstance().log(packet, pkthdr->len);
}

void PcapCapturer::captureThread()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening pcap handle: " << device.c_str() << " === " << errbuf << std::endl;
        return;
    }

    // Start capturing packets
    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this));

    // Cleanup
    pcap_close(handle);
    handle = nullptr;
}

void PcapCapturer::run()
{
    captureThread();
}
