#include "CertUtils/timer_providers/NullTimer.h"
#include "CertUtils/timer_providers/NullTimerSubscriber.h"

namespace
{
    const std::string TIMERS_TASK_NAME = "Timers";
};

using namespace std::literals::chrono_literals;

NullTimer::NullTimer() : TimerFactory()
{
}

TimerFactory::TimerSubscriber_ptr NullTimer::createDeadlineTimer(std::function<void()> const& cb,
                                                                 std::uint64_t expirationSecs)
{
    auto timer = std::make_shared<NullTimerSubscriber>();
    return timer;
}

TimerFactory::TimerSubscriber_ptr NullTimer::createPeriodicTimer(std::function<void()> const& cb,
                                                                 std::uint64_t intervalSecs)
{
    auto timer = std::make_shared<NullTimerSubscriber>();
    return timer;
}
