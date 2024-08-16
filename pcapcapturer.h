#ifndef PCAPCAPTURER_H
#define PCAPCAPTURER_H

#include <QObject>
#include <QThread>
#include <QMutex>
#include <string>
#include <pcap.h>

class PcapCapturer : public QThread
{
    Q_OBJECT

public:
    static PcapCapturer& getInstance();
    ~PcapCapturer();

    void setDev(const std::string& dev);
    void requestStop();

protected:
    void run() override;

private:
    PcapCapturer() : stopRequested(false), handle(nullptr) {}
    void captureThread();
    static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

    std::string device;
    pcap_t *handle;
    QMutex mutex;
    bool stopRequested;
};

#endif // PCAPCAPTURER_H
