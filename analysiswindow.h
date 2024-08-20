// analysiswindow.h

#ifndef ANALYSISWINDOW_H
#define ANALYSISWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QVector>
#include <QPair>
#include <QDateTime>
#include <QCloseEvent>
#include "qcustomplot.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class AnalysisWindow;
}
QT_END_NAMESPACE

class AnalysisWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit AnalysisWindow(QWidget *parent = nullptr);
    ~AnalysisWindow();
    void updateGraph(QString sourceIP, QString destinationIP, int packetSize);
signals:
    void setGraphicEnabled();
protected:
    void closeEvent(QCloseEvent *event) override;

private:
    Ui::AnalysisWindow *ui;
    void setupCustomPlot();
    QCustomPlot *customPlot;
    QTimer *timer;
    QVector<QPair<QDateTime, QPair<QString, int>>> packetData;  // Stores the packet data
};

#endif // ANALYSISWINDOW_H
