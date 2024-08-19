#ifndef CONSOLE_HANDLER_H
#define CONSOLE_HANDLER_H

#include <iostream>
#include <string>

class ConsoleHandler
{
public:
    ConsoleHandler(const ConsoleHandler&) = delete;
    ConsoleHandler& operator=(const ConsoleHandler&) = delete;

    static ConsoleHandler& getInstance()
    {
        static ConsoleHandler instance;

        return instance;

    }
    void print(const std::string& message)
    {
        std::cout << message << std::endl;
    }
    std::string input(const std::string& prompt)
    {
        std::cout << prompt;
        std::string response;
        std::getline(std::cin, response);
        return response;
    }

private:
    ConsoleHandler() {}
};

#endif // CONSOLE_HANDLER_H
