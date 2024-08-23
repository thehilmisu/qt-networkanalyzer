#ifndef NETWORKANALYZER_H
#define NETWORKANALYZER_H

#include <QMainWindow>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QMessageBox>
#include <QTableWidget>
#include <QStandardItem>
#include "pcapinterpreter.h"


class NetworkAnalyzer : public QMainWindow
{
    Q_OBJECT

public:
    explicit NetworkAnalyzer(QWidget *parent = nullptr);
    ~NetworkAnalyzer();

private slots:
    void packetParsed(const PcapFile &pFile);
    void packetItemSelected();
    void onButtonClicked();
    void onNetworkDeviceSelect();
    void networkDeviceSelected();
    void startCapture();



private:
    //UI Elements
    QLabel *lblDeviceName;
    QLabel *lblDeviceLabel;
    QPushButton *btnStartMonitoring;
    QMenu *actionNetworkMenu;
    QMenu *menu;
    QTableWidget *monitoredPackets;
    QTableWidget *packetDetails;
    /////////////////////////////////////
    PcapInterpreter *pcapInterpreter;
    bool isNetworkDeviceSelected;
    bool isCaptureStarted;
    QVector<PcapFile> packets;
    QVector<PcapFile> filteredPackets;
    std::string fileName = "packets.pcap";
    bool isGraphicEnabled;
    void updatePacketDisplay();

};

#endif  //network analyzer