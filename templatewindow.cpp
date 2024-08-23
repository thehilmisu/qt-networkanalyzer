#include "templatewindow.h"

TemplateWindow::TemplateWindow(QWidget *parent)
    : QMainWindow(parent)
{
    // Create the central widget
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // Create the layout
    QVBoxLayout *layout = new QVBoxLayout(centralWidget);

    // Create the label and button
    label = new QLabel("Hello, World!", this);
    button = new QPushButton("Click Me", this);

    // Add the label and button to the layout
    layout->addWidget(label);
    layout->addWidget(button);

    // Connect the button click signal to the slot
    connect(button, &QPushButton::clicked, this, &TemplateWindow::onButtonClicked);

    // Create the menu bar
    QMenuBar *menuBar = new QMenuBar(this);
    setMenuBar(menuBar);

    // Create a menu
    QMenu *fileMenu = menuBar->addMenu("File");

    // Add an action to the menu
    QAction *exitAction = new QAction("Exit", this);
    connect(exitAction, &QAction::triggered, this, &TemplateWindow::close);
    fileMenu->addAction(exitAction);

    // Create the tool bar
    QToolBar *toolBar = new QToolBar(this);
    addToolBar(toolBar);

    // Add an action to the tool bar
    toolBar->addAction(exitAction);

    // Create the status bar
    QStatusBar *statusBar = new QStatusBar(this);
    setStatusBar(statusBar);

    // Display a message in the status bar
    statusBar->showMessage("Ready");
}


void TemplateWindow::onButtonClicked()
{
    QMessageBox::information(this, "Button Clicked", "You clicked the button!");
}
