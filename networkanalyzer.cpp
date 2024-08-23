#include "networkanalyzer.h"

#include <QDebug>
#include <QFile>
#include <QHeaderView>
#include <QTableWidgetItem>
#include <QFileDialog>
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

    QAction *openFileAction = new QAction("Open File", this);
    menu->addAction(openFileAction);
    connect(openFileAction,&QAction::triggered,this,&NetworkAnalyzer::openFileDialog);

    QAction *selectNetworkDeviceAction = new QAction("Select Network Device", this);
    actionNetworkMenu = new QMenu(this);
    selectNetworkDeviceAction->setMenu(actionNetworkMenu);
    connect(menu,&QMenu::aboutToShow,this,&NetworkAnalyzer::onNetworkDeviceSelect);
    menu->addAction(selectNetworkDeviceAction);

    QAction *removePcapAction = new QAction("Remove generated file", this);
    connect(removePcapAction, &QAction::triggered, this, &NetworkAnalyzer::removePcapFile);
    menu->addAction(removePcapAction);

    // exit action
    QAction *exitAction = new QAction("Exit", this);
    connect(exitAction, &QAction::triggered, this, &NetworkAnalyzer::close);
    menu->addAction(exitAction);

    helpMenu = new QMenu("Help",this);
    QAction *about = new QAction("About", this);
    helpMenu->addAction(about);


    menuBar->addMenu(menu);
    menuBar->addMenu(helpMenu);

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

    //graph for the incoming packets
    plotGraph = new QCustomPlot(this);
    setupGraph();
    layout->addWidget(plotGraph);
    
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

    if (analyzeFile != nullptr) {
        delete analyzeFile;
        analyzeFile = nullptr;  // Set to nullptr to avoid double deletion
    }

    delete plotGraph;
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

    updateGraph(pFile.srcIp.c_str(), pFile.dstIp.c_str(), pFile.length);
    
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

void NetworkAnalyzer::setupGraph()
{
    plotGraph->setFixedHeight(250);
    // Set up interactivity
    plotGraph->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom | QCP::iSelectPlottables);

    // Set up the x-axis to show time
    QSharedPointer<QCPAxisTickerDateTime> dateTimeTicker(new QCPAxisTickerDateTime);
    dateTimeTicker->setDateTimeFormat("hh:mm:ss");
    plotGraph->xAxis->setTicker(dateTimeTicker);
    plotGraph->xAxis->setLabel("Time");

    // Set up the y-axis to represent packet data size
    plotGraph->yAxis->setLabel("Packet Size (Bytes)");

    plotGraph->addGraph(); // Create a graph to hold the data
    plotGraph->graph(0)->setLineStyle(QCPGraph::lsNone);
    plotGraph->graph(0)->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssCircle, 5));

    plotGraph->replot();
}

void NetworkAnalyzer::updateGraph(QString sourceIP, QString destinationIP, int packetSize)
{
    QDateTime currentTime = QDateTime::currentDateTime();

    double time = currentTime.toSecsSinceEpoch();
    plotGraph->graph(0)->addData(time, packetSize);

    // Add source and destination IPs as a text label at each point
    QCPItemText *textLabel = new QCPItemText(plotGraph);
    textLabel->position->setCoords(time, packetSize); // Set position of the label
    QString labelText = QString("Src: %1\nDst: %2")
                            .arg(sourceIP)  // Source IP
                            .arg(destinationIP);  // Destination IP
    textLabel->setText(labelText); // Set the IP addresses as the label
    textLabel->setFont(QFont("Helvetica", 9)); // Adjust font size if needed
    textLabel->setColor(Qt::black);
    textLabel->setPositionAlignment(Qt::AlignLeft | Qt::AlignVCenter);

    // Set a reasonable range for the x-axis
    plotGraph->xAxis->setRange(time, 15, Qt::AlignCenter); // Keep the x-axis 60 seconds wide

    // Adjust the y-axis range dynamically
    plotGraph->yAxis->rescale();

    plotGraph->replot();
}

// void MainWindow::onFilterCheckboxStateChanged(int state)
// {
//     PacketFilterManager filterManager;

//     if (state == Qt::Checked)
//     {
//         //TODO: set the filter from user...
//         filterManager.addFilter(QSharedPointer<SourceIpFilter>::create("192.168.1.1"));
//         filterManager.addFilter(QSharedPointer<ProtocolFilter>::create("TCP"));
//         filterManager.addFilter(QSharedPointer<DestinationIpFilter>::create("192.168.1.1"));
//     }

//     filteredPackets = filterManager.applyFilters(packets);
//     updatePacketDisplay();
// }

void NetworkAnalyzer::removePcapFile()
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

void NetworkAnalyzer::openFileDialog()
{
    QString fileName = QFileDialog::getOpenFileName(this, 
                                                    tr("Open File"), 
                                                    "/home/developer/Desktop", 
                                                    tr("All Files (*);;Pcap Files (*.pcap);;"));

    if (!fileName.isEmpty()) 
    {
        if (analyzeFile != nullptr) 
        {
            // Delete the existing instance
            delete analyzeFile;
            analyzeFile = nullptr;  
        }
        
        analyzeFile = new AnalyzeFile(fileName, this);
        analyzeFile->setMinimumWidth(800);
        analyzeFile->setMinimumHeight(750);
        analyzeFile->show();
    }
}
