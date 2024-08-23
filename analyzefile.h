#ifndef ANALYZEFILE_H
#define ANALYZEFILE_H

#include <QMainWindow>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QMessageBox>

class AnalyzeFile : public QMainWindow
{
    Q_OBJECT
public:
    explicit AnalyzeFile(const QString &filePath, QWidget *parent = nullptr);
    ~AnalyzeFile();

private slots:
    void onButtonClicked();

private:
    QString filePath; 
    QLabel *label;
    QPushButton *button;
};

#endif // ANALYZEFILE_H
