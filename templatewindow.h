#ifndef TEMPLATEWINDOW_H
#define TEMPLATEWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QMessageBox>

class TemplateWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit TemplateWindow(QWidget *parent = nullptr);

private slots:
    void onButtonClicked();

private:
    QLabel *label;
    QPushButton *button;
};

#endif // TEMPLATEWINDOW_H
