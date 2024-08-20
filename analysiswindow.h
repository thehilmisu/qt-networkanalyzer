// analysiswindow.h

#ifndef ANALYSISWINDOW_H
#define ANALYSISWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QVector>
#include <QPair>
#include <QDateTime>
#include "qcustomplot.h"

class AnalysisWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit AnalysisWindow(QWidget *parent = nullptr);
    ~AnalysisWindow();

private slots:
    void updateGraph();

private:
    void setupCustomPlot(QCustomPlot *customPlot);

    QCustomPlot *customPlot;
    QTimer *timer;
    QVector<QPair<QDateTime, QPair<QString, int>>> packetData;  // Stores the packet data
};

#endif // ANALYSISWINDOW_H
