#include "timer.hpp"
#include <stdio.h>
#include <utils.hpp>
timer_cpu::timer_cpu(){
    time = 0.0;
}
timer_cpu::~timer_cpu(){
}

void timer_cpu::start(){
    start_time = clock();
}
void timer_cpu::end(){
    time += (double)(clock() - start_time) / CLOCKS_PER_SEC;
}
double timer_cpu::get_time(){
    return time;
}



timer::timer(/* args */)
{
    time = 0;
}

timer::~timer()
{
}

void timer::start(){
    if(ctr > 0){
        printf("Wrong timer\n");
        exit(-1);
    }
    ctr++;
    m_startTime = std::chrono::high_resolution_clock::now();
}
void timer::end(){
    ctr--;
    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = endTime - m_startTime;
    time += duration.count()/1000.0;
}

double timer::get_time(){
    return time;
}
void timer::reset(){
    time = 0.0;
}
