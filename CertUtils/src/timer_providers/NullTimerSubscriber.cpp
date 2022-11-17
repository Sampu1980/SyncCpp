#include "CertUtils/timer_providers/NullTimerSubscriber.h"

NullTimerSubscriber::NullTimerSubscriber()
    : TimerSubscriber()
{
}

bool NullTimerSubscriber::nonBlockCancel()
{
    return true;
}

bool NullTimerSubscriber::cancel()
{
    return true;
}

bool NullTimerSubscriber::nonBlockReset(std::uint64_t secs)
{
    return true;
}

bool NullTimerSubscriber::reset(std::uint64_t secs)
{
    return true;
}
