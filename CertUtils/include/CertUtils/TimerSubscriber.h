#ifndef TIMERSUBSCRIBER_H
#define TIMERSUBSCRIBER_H

#include <cstdint>
#include <ctime>

/**
 * @brief Represents an instance of a Timer(Deadline/Periodic)
 */
class TimerSubscriber
{
    public:
        virtual ~TimerSubscriber()              = default;
        TimerSubscriber()                       = default;              // Default constructor
        TimerSubscriber(const TimerSubscriber&) = delete;               // Copy constructor
        TimerSubscriber& operator=(const TimerSubscriber&) = delete;    // Copy assignment operator

        TimerSubscriber(TimerSubscriber&&) = delete;               // Move constructor
        TimerSubscriber& operator=(TimerSubscriber&&) = delete;    // Move assignment operator

        /**
         * @brief Non-blocking cancelation of timer
         *
         * @return cancelation successfull(true)| cancelation unsuccessfull(false)
         */
        virtual bool nonBlockCancel() = 0;

        /**
         * @brief Blocking cancelation of timer
         *
         * @return operation successfull(true)| operation unsuccessfull(false)
         */
        virtual bool cancel() = 0;

        /**
         * @brief Blocking renewal the underlying timer to a new expiration/interval value in seconds
         *
         * @param secs expiration/interval value in seconds
         * @return operation successfull(true)| operation unsuccessfull(false)
         */
        virtual bool reset(std::uint64_t secs) = 0;

        /**
         * @brief Non-blocking renewal the underlying timer to a new expiration/interval value in seconds
         *
         * @param secs expiration/interval value in seconds
         * @return operation successfull(true)| operation unsuccessfull(false)
         */
        virtual bool nonBlockReset(std::uint64_t secs) = 0;

        /**
         * @brief Check if timer was already cancelled or not
         *
         * @return operation successfull(true)| operation unsuccessfull(false)
         */
        virtual bool isCancelled() = 0;

        /**
         * @brief Gives the number of seconds remaining until deadline expiration
         * This only makes sense in Deadline Timers.
         *
         * @return number of seconds remaining until deadline expiration
         */
        virtual std::uint64_t relativeExpiresIn() = 0;
};
#endif /* TIMERSUBSCRIBER_H */
