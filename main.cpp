#include "networkanalyzer.h"
#include <iostream>
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
   
    NetworkAnalyzer n;
    n.setWindowTitle("Network Analyzer");
    n.setMinimumWidth(800);
    n.setMinimumHeight(750);
    n.show();
   
    return a.exec();
}
