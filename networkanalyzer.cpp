#include "networkanalyzer.h"

#include <QDebug>
#include <QFile>
#include <QHeaderView>
#include <QTableWidgetItem>
#include "packetfiltermanager.h"
#include "sourceipfilter.h"
#include "destinationipfilter.h"
#include "protocolfilter.h"
#include "filemonitor.h"
#include "pcapcapturer.h"
#include "logger.h"
#include "networkdevicefinder.h"

NetworkAnalyzer::NetworkAnalyzer(QWidget *parent)
    : QMainWindow(parent)
    , pcapInterpreter(new PcapInterpreter(this))
    , isNetworkDeviceSelected(false)
    , isGraphicEnabled(false)
    , isCaptureStarted(false)
{
    // Create the central widget
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // Create the layout
    QVBoxLayout *layout = new QVBoxLayout(centralWidget);

    // interface selection group
    QHBoxLayout *hboxInterfaceSelection = new QHBoxLayout();
    lblDeviceName = new QLabel("No interface selected!");
    lblDeviceLabel = new QLabel("Selected interface : ", this);
    btnStartMonitoring = new QPushButton("Start Monitoring", this);

    hboxInterfaceSelection->addWidget(lblDeviceLabel);
    hboxInterfaceSelection->addWidget(lblDeviceName);
    hboxInterfaceSelection->addWidget(btnStartMonitoring);
    layout->addLayout(hboxInterfaceSelection);

    qDebug() << "test";

    // monitoring button
    connect(btnStartMonitoring, &QPushButton::clicked, this, &NetworkAnalyzer::startCapture);

    // Create the menu bar
    QMenuBar *menuBar = new QMenuBar(this);
    setMenuBar(menuBar);

    // Create a menu
    menu = new QMenu("File", this);

    QAction *openFile = new QAction("Open File", this);
    menu->addAction(openFile);

    QAction *selectNetworkDeviceAction = new QAction("Select Network Device", this);
    actionNetworkMenu = new QMenu(this);
    selectNetworkDeviceAction->setMenu(actionNetworkMenu);
    connect(menu,&QMenu::aboutToShow,this,&NetworkAnalyzer::onNetworkDeviceSelect);
    menu->addAction(selectNetworkDeviceAction);

    // exit action
    QAction *exitAction = new QAction("Exit", this);
    connect(exitAction, &QAction::triggered, this, &NetworkAnalyzer::close);
    menu->addAction(exitAction);


    menuBar->addMenu(menu);

    //monitored packet tablewidget
    monitoredPackets = new QTableWidget(this);
    layout->addWidget(monitoredPackets);
    monitoredPackets->setColumnCount(4);
    monitoredPackets->setHorizontalHeaderLabels({"Source IP", "Destination IP", "Protocol", "Length (bytes)"});
    monitoredPackets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    monitoredPackets->setSelectionBehavior(QAbstractItemView::SelectRows);
    monitoredPackets->setSelectionMode(QAbstractItemView::SingleSelection);
    monitoredPackets->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(monitoredPackets,&QTableWidget::itemSelectionChanged,this,&NetworkAnalyzer::packetItemSelected);

    //packet details table widget
    packetDetails = new QTableWidget(this);
    layout->addWidget(packetDetails);
    packetDetails->setColumnCount(3);
    packetDetails->setHorizontalHeaderLabels({"Offset", "Hex Part", "ASCII Part"});
    packetDetails->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    packetDetails->setSelectionMode(QAbstractItemView::NoSelection);
    packetDetails->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packetDetails->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    packetDetails->horizontalHeader()->setStretchLastSection(true);
  
    // Create the status bar
    QStatusBar *statusBar = new QStatusBar(this);
    setStatusBar(statusBar);

    // Display a message in the status bar
    statusBar->showMessage("Ready");


    connect(pcapInterpreter, &PcapInterpreter::packetConstructed, this, &NetworkAnalyzer::packetParsed);
}

NetworkAnalyzer::~NetworkAnalyzer()
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
}


void NetworkAnalyzer::onButtonClicked()
{
    QMessageBox::information(this, "Button Clicked", "You clicked the button!");
}

void NetworkAnalyzer::onNetworkDeviceSelect()
{

    NetworkDeviceFinder& finder = NetworkDeviceFinder::getInstance();
    std::vector<std::string> devices = finder.listDevices();

    QAction *actionNetworkItem = NULL;
    actionNetworkMenu->clear();
    for(int i=0;i<devices.size();++i)
    {
        actionNetworkItem = new QAction(devices.at(i).c_str(), this);
        connect(actionNetworkItem, &QAction::triggered, this, &NetworkAnalyzer::networkDeviceSelected);
        actionNetworkMenu->addAction(actionNetworkItem);

    }

}

void NetworkAnalyzer::networkDeviceSelected()
{
    QAction *action = qobject_cast<QAction*>(sender());
    if (action)
    {
        isNetworkDeviceSelected = true;
        QString deviceName = action->text();
        lblDeviceName->setText(deviceName);

        // Handle the selected network device
        PcapCapturer::getInstance().setDev(deviceName.toStdString());
    }
}

void NetworkAnalyzer::packetParsed(const PcapFile &pFile)
{

    int row = monitoredPackets->rowCount();

    monitoredPackets->insertRow(row);
    monitoredPackets->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(pFile.srcIp)));
    monitoredPackets->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(pFile.dstIp)));
    monitoredPackets->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(pFile.protocol_name)));
    monitoredPackets->setItem(row, 3, new QTableWidgetItem(QString::number(pFile.length)));


    packets.push_back(pFile);

    if(isGraphicEnabled)
    {
        //analysisWindow->updateGraph(pFile.srcIp.c_str(), pFile.dstIp.c_str(), pFile.length);
    }
}

void NetworkAnalyzer::packetItemSelected()
{
    QVector<PacketLineData> packetLines = packets.at(monitoredPackets->currentRow()).packetLineData;

    packetDetails->setRowCount(packetLines.size());
    packetDetails->setColumnCount(3);
    packetDetails->setHorizontalHeaderLabels({"Offset", "Hex Part", "ASCII Part"});

    for (int i = 0; i < packetLines.size(); ++i)
    {
        QTableWidgetItem* offsetItem = new QTableWidgetItem(QString::fromStdString(packetLines[i].offset));
        QTableWidgetItem* hexPartItem = new QTableWidgetItem(QString::fromStdString(packetLines[i].hexPart));
        QTableWidgetItem* asciiPartItem = new QTableWidgetItem(QString::fromStdString(packetLines[i].asciiPart));

        packetDetails->setItem(i, 0, offsetItem);
        packetDetails->setItem(i, 1, hexPartItem);
        packetDetails->setItem(i, 2, asciiPartItem);
    }

}

void NetworkAnalyzer::startCapture()
{

    if(!isCaptureStarted)
    {
        if(isNetworkDeviceSelected)
        {
            btnStartMonitoring->setText("Stop Monitoring");

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
        btnStartMonitoring->setText("Start Monitoring");

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