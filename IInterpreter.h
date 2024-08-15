#ifndef IINTERPRETER_H
#define IINTERPRETER_H

#include <cstddef>

template <typename T>
class IInterpreter
{
public:
    virtual T interpret(const unsigned char* packet, std::size_t length) = 0;
    virtual ~IInterpreter() = default;
};

#endif // IINTERPRETER_H
