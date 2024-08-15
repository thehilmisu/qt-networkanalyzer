#include "logger.h"


Logger& Logger::getInstance()
{
    static Logger instance;

    return instance;
}

Logger::~Logger()
{
    if (m_FileStream.is_open())
    {
        m_FileStream.close();
    }
}

void Logger::log(const unsigned char* packet, std::size_t length)
{
    std::lock_guard<std::mutex> lock(m_Mutex);
    if (m_FileStream.is_open())
    {
        m_FileStream.write(reinterpret_cast<const char*>(packet), length);
    }
}

void Logger::setLogFile(const std::string& filename)
{
    m_FileStream.open(filename, std::ios::binary | std::ios::app);
}
