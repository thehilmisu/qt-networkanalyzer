#ifndef NETWORKANALYZER_H
#define NETWORKANALYZER_H

#include <QMainWindow>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QMessageBox>
#include <QTableWidget>
#include <QStandardItem>
#include "qcustomplot.h"
#include "pcapinterpreter.h"
#include "analyzefile.h"


enum THEME {
    DARK_THEME = 0,
    LIGHT_THEME
};

class NetworkAnalyzer : public QMainWindow
{
    Q_OBJECT

public:
    explicit NetworkAnalyzer(QWidget *parent = nullptr);
    ~NetworkAnalyzer();

private slots:
    void packetParsed(const PcapFile &pFile);
    void packetItemSelected();
    void onNetworkDeviceSelect();
    void networkDeviceSelected();
    void startCapture();
    void removePcapFile();
    void openFileDialog();
    void onFilterCheckboxStateChanged(int state);
    void lightTheme();
    void darkTheme();

private:
    //UI Elements
    QLabel *lblDeviceName;
    QPushButton *btnStartMonitoring;
    QMenu *actionNetworkMenu;
    QMenu *menu;
    QMenu *exportMenu;
    QMenu *helpMenu;
    QTableWidget *monitoredPackets;
    QTableWidget *packetDetails;
    QLabel *lblFilter;
    QLabel *lblFilterText;
    QCheckBox *chkFilterEnabled;
    QComboBox *comboFilterType;
    QLineEdit *txtFilter;
    QGroupBox *interfaceGroupBox;
    QGroupBox *filterGroupBox;
    /////////////////////////////////////
    PcapInterpreter *pcapInterpreter;
    QCustomPlot *plotGraph;
    AnalyzeFile *analyzeFile = nullptr;
    QVector<double> timeData;
    bool isNetworkDeviceSelected;
    bool isCaptureStarted;
    QVector<PcapFile> packets;
    QVector<PcapFile> filteredPackets;
    std::string fileName = "packets.pcap";
    void updatePacketDisplay();
    void setupGraph();
    void updateGraph(QString sourceIP, QString destinationIP, int packetSize);

};

#endif  //network analyzer