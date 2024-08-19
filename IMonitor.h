#ifndef IMONITOR_H
#define IMONITOR_H


class IMonitor
{
public:
    virtual void monitor() = 0;
    virtual ~IMonitor() = default;
};


#endif // IMONITOR_H
