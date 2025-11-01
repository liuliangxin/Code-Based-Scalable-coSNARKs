#pragma once
//#include "config_pc.hpp"
#include <chrono>

class timer_cpu
{
private:
    double time;
    clock_t start_time;
public:
    timer_cpu();
    ~timer_cpu();
    void start();
    void end();
    double get_time();
};


class timer
{
private:
    double time;
    int ctr = 0;
    std::chrono::time_point<std::chrono::high_resolution_clock> m_startTime;
public:
    timer();
    ~timer();
    void start();
    void end();
    void reset();
    double get_time();
};
