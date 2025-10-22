#include "config_pc.hpp"
#include <chrono>
class timer
{
private:
    double time;
    chrono::time_point<std::chrono::high_resolution_clock> m_startTime;
public:
    timer();
    ~timer();
    void start();
    void end();
};

timer::timer(/* args */)
{
    time = 0;
}

timer::~timer()
{
}

void timer::start(){
    m_startTime = std::chrono::high_resolution_clock::now();
}
void timer::end(){
    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = endTime - m_startTime;
    time = duration.count()/1000.0;
}
