// analysiswindow.cpp

#include "analysiswindow.h"
#include <QVBoxLayout>

AnalysisWindow::AnalysisWindow(QWidget *parent)
    : QMainWindow(parent)
{
    // Initialize the custom plot
    customPlot = new QCustomPlot(this);
    setCentralWidget(customPlot);

    // Set up the graph
    setupCustomPlot(customPlot);

    // Initialize the timer
    timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &AnalysisWindow::updateGraph);
    timer->start(1000); // Update every second
}

AnalysisWindow::~AnalysisWindow()
{
    delete customPlot;
    delete timer;
}

void AnalysisWindow::setupCustomPlot(QCustomPlot *customPlot)
{
    // Set up interactivity
    customPlot->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom | QCP::iSelectPlottables);

    // Set up the x-axis to show time
    QSharedPointer<QCPAxisTickerDateTime> dateTimeTicker(new QCPAxisTickerDateTime);
    dateTimeTicker->setDateTimeFormat("hh:mm:ss");
    customPlot->xAxis->setTicker(dateTimeTicker);
    customPlot->xAxis->setLabel("Time");

    // Set up the y-axis to represent packet data size
    customPlot->yAxis->setLabel("Packet Size (Bytes)");

    customPlot->addGraph(); // Create a graph to hold the data
    customPlot->graph(0)->setLineStyle(QCPGraph::lsNone);
    customPlot->graph(0)->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssCircle, 5));

    customPlot->replot();
}

void AnalysisWindow::updateGraph()
{
    // Simulate receiving a new packet
    QDateTime currentTime = QDateTime::currentDateTime();
    QString sourceIP = QString("192.168.1.%1").arg(1 + (rand() % 10)); // Random source IP
    QString destinationIP = QString("192.168.1.%1").arg(1 + (rand() % 10)); // Random destination IP
    int packetSize = 500 + (rand() % 1500); // Random packet size between 500 and 2000 bytes

    // Store the new packet data
    packetData.append(qMakePair(currentTime, qMakePair(sourceIP, packetSize)));

    // Add the new data to the graph
    double time = currentTime.toSecsSinceEpoch();
    customPlot->graph(0)->addData(time, packetSize);

    // Add source and destination IPs as a text label at each point
    QCPItemText *textLabel = new QCPItemText(customPlot);
    textLabel->position->setCoords(time, packetSize); // Set position of the label
    QString labelText = QString("Src: %1\nDst: %2")
                            .arg(sourceIP)  // Source IP
                            .arg(destinationIP);  // Destination IP
    textLabel->setText(labelText); // Set the IP addresses as the label
    textLabel->setFont(QFont("Helvetica", 9)); // Adjust font size if needed
    textLabel->setColor(Qt::black);
    textLabel->setPositionAlignment(Qt::AlignLeft | Qt::AlignVCenter);

    // Set a reasonable range for the x-axis
    customPlot->xAxis->setRange(time, 15, Qt::AlignCenter); // Keep the x-axis 60 seconds wide

    // Adjust the y-axis range dynamically
    customPlot->yAxis->rescale();

    customPlot->replot();
}

