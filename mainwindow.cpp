#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QDebug>
#include <QFile>
#include "packetfiltermanager.h"
#include "sourceipfilter.h"
#include "destinationipfilter.h"
#include "protocolfilter.h"
#include "filemonitor.h"
#include "pcapcapturer.h"
#include "logger.h"
#include "networkdevicefinder.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , pcapInterpreter(new PcapInterpreter(this))
    , isNetworkDeviceSelected(false)
    , isGraphicEnabled(false)
    , isCaptureStarted(false)
{
    ui->setupUi(this);

    packets.clear();

    actionNetworkMenu = new QMenu(this);
    ui->actionSelect_network_device->setMenu(actionNetworkMenu);

    connect(ui->menuFile,&QMenu::aboutToShow,this,&MainWindow::onNetworkDeviceSelect);
    connect(ui->actionRemove_pcap_file,&QAction::triggered,this,&MainWindow::removePcapFile);
    connect(ui->actionExit_2,&QAction::triggered,this,&MainWindow::close);
    connect(ui->actionOpen_File,&QAction::triggered,this,&MainWindow::openFile);

    connect(ui->btnStartCapture, &QPushButton::clicked, this, &MainWindow::startCapture);

    connect(pcapInterpreter, &PcapInterpreter::packetConstructed, this, &MainWindow::packetParsed);

    ui->monitoredPackets->setColumnCount(4);
    ui->monitoredPackets->setHorizontalHeaderLabels({"Source IP", "Destination IP", "Protocol", "Length (bytes)"});
    ui->monitoredPackets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->monitoredPackets->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->monitoredPackets->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->monitoredPackets->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(ui->monitoredPackets,&QTableWidget::itemSelectionChanged,this,&MainWindow::packetItemSelected);

    ui->filterTypeCombo->addItem("Source IP");
    ui->filterTypeCombo->addItem("Destination IP");
    ui->filterTypeCombo->addItem("Protocol Type");


    ui->tableWidget->setColumnCount(3);
    ui->tableWidget->setHorizontalHeaderLabels({"Offset", "Hex Part", "ASCII Part"});
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableWidget->setSelectionMode(QAbstractItemView::NoSelection);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);

    analysisWindow = new AnalysisWindow(this);
    connect(ui->btnAnalyze, &QPushButton::clicked,this,&MainWindow::showGraphicalData);
    connect(analysisWindow, &AnalysisWindow::setGraphicEnabled,this,&MainWindow::setGraphicEnable);


}

MainWindow::~MainWindow()
{
    // Stop and wait for PcapCapturer thread
    PcapCapturer &pcapCapturer = PcapCapturer::getInstance();
    pcapCapturer.requestStop();
    pcapCapturer.wait();  // Wait until the thread is finished
    pcapCapturer.deleteLater();

    // Stop and wait for FileMonitor thread
    FileMonitor &fileMonitor = FileMonitor::getInstance();
    fileMonitor.requestStop();
    fileMonitor.wait();  // Wait until the thread is finished
    fileMonitor.deleteLater();

    delete ui;
}

void MainWindow::showGraphicalData()
{
    isGraphicEnabled = true;
    analysisWindow->show();
}

void MainWindow::setGraphicEnable()
{
    isGraphicEnabled = false;
}

void MainWindow::startCapture()
{

    if(!isCaptureStarted)
    {
        if(isNetworkDeviceSelected)
        {
            ui->btnStartCapture->setText("Stop Capture");

            Logger::getInstance().setLogFile(fileName);

            PcapCapturer::getInstance().start();

            FileMonitor::getInstance().setFileName(fileName);
            FileMonitor::getInstance().setPcapInterpreter(pcapInterpreter);
            FileMonitor::getInstance().start();

            isCaptureStarted = true;
        }
        else
        {
            QMessageBox::warning(this,"Warning","Select a network interface first");
        }
    }
    else
    {
        ui->btnStartCapture->setText("Start Capture");

        // Stop and wait for PcapCapturer thread
        PcapCapturer &pcapCapturer = PcapCapturer::getInstance();
        pcapCapturer.requestStop();
        pcapCapturer.wait();  // Wait until the thread is finished


        // Stop and wait for FileMonitor thread
        FileMonitor &fileMonitor = FileMonitor::getInstance();
        fileMonitor.requestStop();
        fileMonitor.wait();  // Wait until the thread is finished

        isCaptureStarted = false;
        isGraphicEnabled = false;

    }

}

void MainWindow::packetParsed(const PcapFile &pFile)
{

    int row = ui->monitoredPackets->rowCount();

    ui->monitoredPackets->insertRow(row);
    ui->monitoredPackets->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(pFile.srcIp)));
    ui->monitoredPackets->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(pFile.dstIp)));
    ui->monitoredPackets->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(pFile.protocol_name)));
    ui->monitoredPackets->setItem(row, 3, new QTableWidgetItem(QString::number(pFile.length)));


    packets.push_back(pFile);

    if(isGraphicEnabled)
    {
        analysisWindow->updateGraph(pFile.srcIp.c_str(), pFile.dstIp.c_str(), pFile.length);
    }
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

void MainWindow::openFile()
{

}

void MainWindow::onFilterCheckboxStateChanged(int state)
{
    PacketFilterManager filterManager;

    if (state == Qt::Checked)
    {
        //TODO: set the filter from user...
        filterManager.addFilter(QSharedPointer<SourceIpFilter>::create("192.168.1.1"));
        filterManager.addFilter(QSharedPointer<ProtocolFilter>::create("TCP"));
        filterManager.addFilter(QSharedPointer<DestinationIpFilter>::create("192.168.1.1"));
    }

    filteredPackets = filterManager.applyFilters(packets);
    updatePacketDisplay();
}

void MainWindow::updatePacketDisplay()
{
    ui->monitoredPackets->clear();  // Clear current display

    for (const auto& packet : filteredPackets)
    {
        int row = ui->monitoredPackets->rowCount();

        ui->monitoredPackets->insertRow(row);
        ui->monitoredPackets->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(packet.srcIp)));
        ui->monitoredPackets->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(packet.dstIp)));
        ui->monitoredPackets->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(packet.protocol_name)));
        ui->monitoredPackets->setItem(row, 3, new QTableWidgetItem(QString::number(packet.length)));
    }
}

void MainWindow::packetItemSelected()
{
    QVector<PacketLineData> packetLines = packets.at(ui->monitoredPackets->currentRow()).packetLineData;

    ui->tableWidget->setRowCount(packetLines.size());
    ui->tableWidget->setColumnCount(3);
    ui->tableWidget->setHorizontalHeaderLabels({"Offset", "Hex Part", "ASCII Part"});

    for (int i = 0; i < packetLines.size(); ++i)
    {
        QTableWidgetItem* offsetItem = new QTableWidgetItem(QString::fromStdString(packetLines[i].offset));
        QTableWidgetItem* hexPartItem = new QTableWidgetItem(QString::fromStdString(packetLines[i].hexPart));
        QTableWidgetItem* asciiPartItem = new QTableWidgetItem(QString::fromStdString(packetLines[i].asciiPart));

        ui->tableWidget->setItem(i, 0, offsetItem);
        ui->tableWidget->setItem(i, 1, hexPartItem);
        ui->tableWidget->setItem(i, 2, asciiPartItem);
    }

    /*
    ui->plainTextEdit->clear();

    //const auto& packetData = packets.at(ui->monitoredPackets->currentRow()).data;
    QString formattedText = packets.at(ui->monitoredPackets->currentRow()).formattedData;
    QString detectedLinks = packets.at(ui->monitoredPackets->currentRow()).detectedLinks;

    ui->plainTextEdit->appendPlainText(formattedText);

    ConsoleHandler::getInstance().print(detectedLinks.toStdString());*/

}

void MainWindow::removePcapFile()
{
    QFile file(fileName.c_str());

    if (file.exists())
    {
        if (file.remove())
        {
            QMessageBox::information(this, "File Removal", "File deleted successfully");
        }
        else
        {
            QMessageBox::information(this, "File Removal", "Failed to delete file, check if capturing in progress");
        }
    }
    else
    {
        QMessageBox::information(this, "File Removal", "File does not exists");
    }
}
