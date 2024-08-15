#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    NetworkDeviceFinder& finder = NetworkDeviceFinder::getInstance();

    std::string fileName = "packets.pcap";
    std::vector<std::string> devices = finder.listDevices();

    for(int i=0;i<devices.size();++i)
        qDebug() << devices.at(i).c_str() << "\n";

    Logger& logger = Logger::getInstance();
    logger.setLogFile(fileName);

    PcapCapturer& capturer = PcapCapturer::getInstance();
    capturer.setDev(devices.at(1));
    capturer.start();

    FileMonitor& monitor = FileMonitor::getInstance();
    monitor.setFileName(fileName);
    monitor.start();


}

MainWindow::~MainWindow()
{
    delete ui;
}
