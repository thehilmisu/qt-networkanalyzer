#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItem>
#include <QMessageBox>
#include "filemonitor.h"
#include "pcapcapturer.h"
#include "logger.h"
#include "networkdevicefinder.h"
#include "pcapinterpreter.h"



QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void startCapture();
    void packetParsed(const PcapFile &pFile);
    void packetItemSelected();
    void onNetworkDeviceSelect();
    void networkDeviceSelected();
    void removePcapFile();
    void onFilterCheckboxStateChanged(int state);

private:
    Ui::MainWindow *ui;
    PcapInterpreter *pcapInterpreter;
    QMenu *actionNetworkMenu;
    bool isNetworkDeviceSelected;
    bool isCaptureStarted;
    QVector<PcapFile> packets;
    QVector<PcapFile> filteredPackets;
    std::string fileName = "packets.pcap";
    void updatePacketDisplay();

};
#endif // MAINWINDOW_H
