#ifndef UTCP_TIMER_HPP
#define UTCP_TIMER_HPP

#include <chrono>
#include <functional>

using SystemTimePoint = std::chrono::time_point<std::chrono::system_clock>;

struct Timer{
    SystemTimePoint expired;
    std::function<void()> handler;
};

#endif