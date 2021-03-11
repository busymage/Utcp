#ifndef UTCP_TIMER_HPP
#define UTCP_TIMER_HPP

#include <chrono>
#include <functional>

using HrTimePoint = std::chrono::time_point<std::chrono::high_resolution_clock>;

struct Timer{
    HrTimePoint expired;
    std::function<void()> handler;
};

#endif