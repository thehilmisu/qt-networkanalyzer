#include "pcapcapturer.h"
#include "logger.h"
#include <iostream>

// Singleton instance of Application
PcapCapturer& PcapCapturer::getInstance() {
    static PcapCapturer instance;
    return instance;
}

// Destructor
PcapCapturer::~PcapCapturer() {
    // Ensure the thread is safely stopped before destruction
    if (isRunning()) {
        quit();
        wait();
    }
}

void PcapCapturer::setDev(const std::string& dev) {
    device = dev.c_str();
    //std::cout << device.toStdString().c_str() << dev.c_str() << std::endl;
}

void PcapCapturer::packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    Logger::getInstance().log(packet, pkthdr->len);
}

void PcapCapturer::captureThread() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening pcap handle: " << device.c_str() << " === " << errbuf << std::endl;
        return;
    }

    // Using packetHandlerWrapper with pcap_loop
    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this));
    pcap_close(handle);
}

// The run() method is called when the thread is started
void PcapCapturer::run() {
    captureThread();
}
