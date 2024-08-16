#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , pcapInterpreter(new PcapInterpreter(this))
{
    ui->setupUi(this);

    isNetworkDeviceSelected = false;
    packets.clear();

    actionNetworkMenu = new QMenu(this);
    ui->actionSelect_network_device->setMenu(actionNetworkMenu);

    connect(ui->menuFile,&QMenu::aboutToShow,this,&MainWindow::onNetworkDeviceSelect);

    connect(ui->actionRemove_pcap_file,&QAction::triggered,this,&MainWindow::removePcapFile);

    connect(ui->actionExit_2,&QAction::triggered,this,&MainWindow::close);

    connect(ui->btnStartCapture, &QPushButton::clicked, this, &MainWindow::startCapture);

    connect(pcapInterpreter, &PcapInterpreter::packetConstructed, this, &MainWindow::packetParsed);

    connect(ui->monitoredPackets,&QListWidget::itemSelectionChanged,this,&MainWindow::packetItemSelected);

}

MainWindow::~MainWindow()
{
    PcapCapturer::getInstance().deleteLater();
    FileMonitor::getInstance().deleteLater();
    delete ui;
}


void MainWindow::startCapture()
{
    if(isNetworkDeviceSelected)
    {

        Logger::getInstance().setLogFile(fileName);

        PcapCapturer::getInstance().start();

        FileMonitor::getInstance().setFileName(fileName);
        FileMonitor::getInstance().setPcapInterpreter(pcapInterpreter);
        FileMonitor::getInstance().start();
    }
    else
    {
        QMessageBox::warning(this,"Warning","Select a network interface first");
    }

}

void MainWindow::packetParsed(const PcapFile &pFile)
{
    QString itemText = QString("%1 ---> %2    |   %3   |    %4 bytes")
                           .arg(QString::fromStdString(pFile.srcIp))
                           .arg(QString::fromStdString(pFile.dstIp))
                           .arg(QString::fromStdString(pFile.protocol_name))
                           .arg(pFile.length);

    ui->monitoredPackets->addItem(itemText);

    //ui->monitoredPackets->scrollToBottom();

    packets.push_back(pFile);
}

void MainWindow::onNetworkDeviceSelect()
{

    NetworkDeviceFinder& finder = NetworkDeviceFinder::getInstance();
    std::vector<std::string> devices = finder.listDevices();

    QAction *actionNetworkItem = NULL;
    actionNetworkMenu->clear();
    for(int i=0;i<devices.size();++i)
    {
        actionNetworkItem = new QAction(devices.at(i).c_str(), this);
        connect(actionNetworkItem, &QAction::triggered, this, &MainWindow::networkDeviceSelected);
        //actionNetworkItem->setMenu(actionNetworkMenu);
        actionNetworkMenu->addAction(actionNetworkItem);

    }

}

void MainWindow::networkDeviceSelected()
{
    QAction *action = qobject_cast<QAction*>(sender());
    if (action)
    {
        isNetworkDeviceSelected = true;
        QString deviceName = action->text();
        ui->lblSelectedInterface->setText(deviceName);
        //qDebug() << "Selected network device:" << deviceName;

        // Handle the selected network device
        PcapCapturer::getInstance().setDev(deviceName.toStdString());
    }
}



void MainWindow::packetItemSelected()
{
    ui->plainTextEdit->clear();

    //const auto& packetData = packets.at(ui->monitoredPackets->currentRow()).data;
    QString formattedText = packets.at(ui->monitoredPackets->currentRow()).formattedData;

    ui->plainTextEdit->appendPlainText(formattedText);

}

void MainWindow::removePcapFile()
{
    QFile file(fileName.c_str());

    if (file.exists()) {
        if (file.remove()) {
            QMessageBox::information(this, "File Removal", "File deleted successfully");
        } else {
            QMessageBox::information(this, "File Removal", "Failed to delete file, check if capturing in progress");
        }
    } else {
        QMessageBox::information(this, "File Removal", "File does not exists");
    }
}
