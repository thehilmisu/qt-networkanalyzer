#ifndef PCAPCAPTURER_H
#define PCAPCAPTURER_H

#include <QObject>
#include <QThread>
#include <string>
#include <pcap.h>

class PcapCapturer : public QThread
{
    Q_OBJECT

public:
    static PcapCapturer& getInstance();
    void setDev(const std::string& dev);

protected:
    void run() override;

private:
    PcapCapturer() = default;
    ~PcapCapturer();
    PcapCapturer(const PcapCapturer&) = delete;
    PcapCapturer& operator=(const PcapCapturer&) = delete;

    static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    static void packetHandlerWrapper(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        PcapCapturer* app = reinterpret_cast<PcapCapturer*>(userData);
        app->packetHandler(userData, pkthdr, packet);
    }

    void captureThread();

    std::string device;

};

#endif // PCAPCAPTURER_H
