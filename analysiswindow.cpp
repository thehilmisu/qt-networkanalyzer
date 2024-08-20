// analysiswindow.cpp

#include <iostream>
#include "analysiswindow.h"
#include <QVBoxLayout>
#include "./ui_analysiswindow.h"

AnalysisWindow::AnalysisWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::AnalysisWindow)
{

    ui->setupUi(this);

    customPlot = new QCustomPlot(this);

    ui->verticalLayout->addWidget(customPlot);

    setupCustomPlot();

}

AnalysisWindow::~AnalysisWindow()
{
    delete customPlot;
    delete timer;
}

void AnalysisWindow::closeEvent(QCloseEvent *event)
{
    std::cout << "window closed" << std::endl;
    emit setGraphicEnabled();
}

void AnalysisWindow::setupCustomPlot()
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

void AnalysisWindow::updateGraph(QString sourceIP, QString destinationIP, int packetSize)
{
    QDateTime currentTime = QDateTime::currentDateTime();

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

