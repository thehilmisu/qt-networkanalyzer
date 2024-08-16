#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , pcapInterpreter(new PcapInterpreter(this))
{
    ui->setupUi(this);

    connect(ui->btnScanDevices, &QPushButton::clicked, this, &MainWindow::scanDevicesClicked);
    connect(ui->devicesCombo, &QComboBox::currentTextChanged,this, &MainWindow::networkDeviceSelectionChanged);
    connect(ui->btnStartCapture, &QPushButton::clicked, this, &MainWindow::startCapture);

    bool connected = connect(pcapInterpreter, &PcapInterpreter::packetConstructed, this, &MainWindow::packetParsed);

}

MainWindow::~MainWindow()
{
    //TODO: handle the threads on destructor
    delete ui;
}

void MainWindow::scanDevicesClicked()
{
    ui->devicesCombo->clear();

    NetworkDeviceFinder& finder = NetworkDeviceFinder::getInstance();
    std::vector<std::string> devices = finder.listDevices();

    QStringList availableDevices;
    for(int i=0;i<devices.size();++i)
        availableDevices << devices.at(i).c_str();

    ui->devicesCombo->addItems(availableDevices);

}

void MainWindow::networkDeviceSelectionChanged(const QString& selectedItem)
{
    std::cout << selectedItem.toStdString() << std::endl;
    PcapCapturer::getInstance().setDev(selectedItem.toStdString());
}

void MainWindow::startCapture()
{
    std::string fileName = "packets.pcap";
    Logger::getInstance().setLogFile(fileName);

    PcapCapturer::getInstance().start();

    FileMonitor::getInstance().setFileName(fileName);
    FileMonitor::getInstance().setPcapInterpreter(pcapInterpreter);
    FileMonitor::getInstance().start();
}

void MainWindow::packetParsed(const PcapFile &pFile)
{
    //

    QString itemText = QString("%1 -> %2 | %3 | %4 bytes")
                           .arg(QString::fromStdString(pFile.srcIp))
                           .arg(QString::fromStdString(pFile.dstIp))
                           .arg(QString::fromStdString(pFile.protocol_name))
                           .arg(pFile.length);

    ui->monitoredPackets->addItem(itemText);
}
