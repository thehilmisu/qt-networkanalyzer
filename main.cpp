#include "networkanalyzer.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    NetworkAnalyzer n;
    n.resize(700,500);
    n.show();
   
    return a.exec();
}
