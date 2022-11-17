#ifndef TIMERFACTORY_H
#define TIMERFACTORY_H

#include <memory>
#include <functional>
#include <cstdint>
#include "CertUtils/TimerSubscriber.h"

/**
 * @brief Deadline and Periodic Timers Factory interface
 */
class TimerFactory
{
    public:
        virtual ~TimerFactory()           = default;
        TimerFactory()                    = default;              // Default constructor
        TimerFactory(const TimerFactory&) = delete;               // Copy constructor
        TimerFactory& operator=(const TimerFactory&) = delete;    // Copy assignment operator

        TimerFactory(TimerFactory&&) = delete;               // Move constructor
        TimerFactory& operator=(TimerFactory&&) = delete;    // Move assignment operator

        using TimerSubscriber_ptr = std::shared_ptr<TimerSubscriber>;

        /**
         * @brief Creates a Deadline TimerSubscriber object
         *
         * @param cb Callback to run when deadline timer expiration occurs
         * @param expirationSecs expiration in seconds
         * @return Deadline TimerSubscriber shared_ptr
         */
        virtual TimerSubscriber_ptr createDeadlineTimer(std::function<void()> const& cb, std::uint64_t expirationSecs) = 0;

        /**
         * @brief Create a Periodic TimerSubscriber object
         *
         * @param cb Callback to run at every periodic interval
         * @param intervalSecs interval in seconds
         * @return Periodic TimerSubscriber shared_ptr
         */
        virtual TimerSubscriber_ptr createPeriodicTimer(std::function<void()> const& cb, std::uint64_t intervalSecs) = 0;
};
#endif /* TIMERFACTORY_H */
