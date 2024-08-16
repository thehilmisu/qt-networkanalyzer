#ifndef FILEMONITOR_H
#define FILEMONITOR_H

#include <QThread>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include "pcapinterpreter.h"
#include "IMonitor.h"

class FileMonitor : public QThread, public IMonitor
{
    Q_OBJECT

public:
    static FileMonitor& getInstance();
    void setFileName(const std::string& fileName);
    void setFilePosition(std::streampos position);
    void setPcapInterpreter(PcapInterpreter *pcapInterpreter);

protected:
    void run() override;

private:
    FileMonitor() = default;
    ~FileMonitor();
    FileMonitor(const FileMonitor&) = delete;
    FileMonitor& operator=(const FileMonitor&) = delete;

    void monitor() override;

    std::string m_Filename;
    std::streampos m_FilePosition;
    PcapInterpreter *m_Interpreter;
};

#endif // FILEMONITOR_H
