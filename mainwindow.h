#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItem>
#include "filemonitor.h"
#include "pcapcapturer.h"
#include "logger.h"
#include "networkdevicefinder.h"
#include "pcapinterpreter.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void scanDevicesClicked();
    void startCapture();
    void networkDeviceSelectionChanged(const QString& selectedItem);
    void packetParsed(const PcapFile &pFile);
private:
    Ui::MainWindow *ui;
    PcapInterpreter *pcapInterpreter;


};
#endif // MAINWINDOW_H
