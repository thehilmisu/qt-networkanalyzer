#ifndef LOGGER_H
#define LOGGER_H

#include <fstream>
#include <mutex>
#include <string>

class Logger
{
public:
    static Logger& getInstance();
    void log(const unsigned char* packet, std::size_t length);
    void setLogFile(const std::string& filename);

private:
    Logger() = default;
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::ofstream m_FileStream;
    std::mutex m_Mutex;
};

#endif // LOGGER_H
