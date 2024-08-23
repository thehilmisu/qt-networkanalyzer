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
        analyzeFile = nullptr;  
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

    setupGraph();
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
    timeData.clear();
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
    plotGraph->addGraph();
    plotGraph->setMinimumHeight(300);

    // Set graph line style to none (no line between points)
    plotGraph->graph(0)->setLineStyle(QCPGraph::lsNone);

    plotGraph->graph(0)->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssCircle, 5));

    // Configure x-axis to show time
    QSharedPointer<QCPAxisTickerDateTime> dateTimeTicker(new QCPAxisTickerDateTime);
    dateTimeTicker->setDateTimeFormat("hh:mm:ss");
    plotGraph->xAxis->setTicker(dateTimeTicker);
    plotGraph->xAxis->setLabel("Time");

    // Configure y-axis label
    plotGraph->yAxis->setLabel("Packet Size");

    // Set initial ranges (adjust these based on your expected data)
    plotGraph->xAxis->setRange(QDateTime::currentDateTime().toSecsSinceEpoch(), 60, Qt::AlignRight);
    plotGraph->yAxis->setRange(0, 100); // Adjust as needed

    // Enable interactions
    plotGraph->setInteraction(QCP::iRangeDrag, true);
    plotGraph->setInteraction(QCP::iRangeZoom, true);
    plotGraph->axisRect()->setRangeDrag(Qt::Horizontal);
    plotGraph->axisRect()->setRangeZoom(Qt::Horizontal);
    plotGraph->axisRect()->setRangeZoomFactor(0.9);

    // Initial replot to ensure the plot is rendered
    plotGraph->replot();

    // Force an initial x-axis range and replot
    double currentTimeSecs = QDateTime::currentDateTime().toSecsSinceEpoch();
    plotGraph->xAxis->setRange(currentTimeSecs, currentTimeSecs + 10); // Start with a small range
    plotGraph->replot();
}

void NetworkAnalyzer::updateGraph(QString sourceIP, QString destinationIP, int packetSize)
{
    QDateTime currentTime = QDateTime::currentDateTime();
    double currentTimeSecs = currentTime.toSecsSinceEpoch();

    // Append new data to the containers
    timeData.append(currentTimeSecs);
   

    // Add data to the graph
    plotGraph->graph(0)->addData(currentTimeSecs, packetSize);

    // Add text label at the data point
    QCPItemText *textLabel = new QCPItemText(plotGraph);
    textLabel->position->setCoords(currentTimeSecs, packetSize);
    QString labelText = QString("Src: %1\nDst: %2").arg(sourceIP).arg(destinationIP);
    textLabel->setText(labelText);
    textLabel->setFont(QFont("Helvetica", 8));
    textLabel->setColor(Qt::black);
    textLabel->setPositionAlignment(Qt::AlignLeft | Qt::AlignVCenter);

    // Adjust y-axis range
    plotGraph->yAxis->rescale(true);
    double yLower = plotGraph->yAxis->range().lower;
    double yUpper = plotGraph->yAxis->range().upper;
    double yMargin = (yUpper - yLower) * 0.1; // 10% margin

    plotGraph->yAxis->setRange(yLower - yMargin, yUpper + yMargin);

    // Determine the current x-axis range
    double xAxisUpper = plotGraph->xAxis->range().upper;
    double xAxisLower = plotGraph->xAxis->range().lower;
    double xMargin = (xAxisUpper - xAxisLower) * 0.2; 

    // Define the number of points to display
    int pointsToShow = 5;

    // Calculate lower bound for x-axis
    double xLowerBound;
    if (timeData.size() <= pointsToShow)
    {
        xLowerBound = timeData.first();
    }
    else
    {
        xLowerBound = timeData[timeData.size() - pointsToShow];
    }

    plotGraph->xAxis->setRange(xLowerBound, timeData.last() + xMargin);

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
