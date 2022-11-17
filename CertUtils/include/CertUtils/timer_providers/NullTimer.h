#ifndef NULLTIMER_H
#define NULLTIMER_H

#include "CertUtils/TimerFactory.h"
#include "logger.h"

/**
 * @brief Implementation of a null TimerFactory
 */
class NullTimer : public TimerFactory
{
    public:
        NullTimer();
        NullTimer(const NullTimer&) = delete;               // Copy constructor
        NullTimer& operator=(const NullTimer&) = delete;    // Copy assignment operator

        NullTimer(NullTimer&&) = delete;               // Move constructor
        NullTimer& operator=(NullTimer&&) = delete;    // Move assignment operator
        virtual ~NullTimer()              = default;

        TimerFactory::TimerSubscriber_ptr createDeadlineTimer(std::function<void()> const& cb,
                                                              std::uint64_t expirationSecs) override;

        TimerFactory::TimerSubscriber_ptr createPeriodicTimer(std::function<void()> const& cb,
                                                              std::uint64_t intervalSecs) override;
};
#endif /* NULLTIMER_H */
