#ifndef TIMERREAL_H
#define TIMERREAL_H

#include "TimerInterface.h"
#include "app-utils/TaskRunner.h"
#include <mutex>
#include <thread>
#include <condition_variable>
#include <boost/optional.hpp>

namespace appUtils
{
    /**
     * @brief Implements the TimerInterface using an std::steady_clock (monotonic).
     * The timeouts implemented with this implementation will not suffer side effects of clock adjustments
     * (no missed timeouts, total timeout is at least the amount requested, even if system clock is adjusted).
     */
    class TimerReal: public TimerInterface
    {
        public:
            explicit TimerReal(std::weak_ptr<TimerCallbacks> callbacks = std::weak_ptr<TimerCallbacks>());
            ~TimerReal() override;

            Id startTimer(std::string const& humanReadableDescription, std::chrono::seconds duration) override;

            void cancelTimer(Id id) override;

            std::vector<TimerInfo> getActiveTimers() const override;

            void addTimerClient(std::weak_ptr<TimerCallbacks> client) override;

        private:
            /**
             * @brief Internal representation of timers.
             * Differs slightly from TimerInfo in how times are stored (end time + start time) vs (start time + duration)
             */
            struct InternalTimerInfo
            {
                std::chrono::time_point<std::chrono::steady_clock> endTime;
                std::chrono::time_point<std::chrono::steady_clock> startTime;
                Id id;
                std::string humanReadableDescription;

                /**
                 * Sorting of timers is done by end time.
                 * This ensures the next timer on the internal list to be the one next one to expire.
                 */
                bool operator<(InternalTimerInfo const& rhs) const;
            };

            /**
             * To be launched in its own thread, handles the timers.
             */
            void threadLoop();

            /**
             * Executed after each sleep and when internal thread is woken up for some other reason.
             * Checks if there are any expired timers. If there are, removes them from myTimers
             * and invokes their callbacks.
             */
            void processExpiredTimers();

            /**
             * Check what is the next timer, so that the internal thread can sleep for the correct amount of time.
             */
            boost::optional<InternalTimerInfo> selectNextTimer(std::unique_lock<std::mutex> const& lock) const;

            bool isThreadInitialized() const;
            void initializeThread();

            /**
             * Wake up internal thread, so that it can check if there are actions to take.
             */
            void notifyThreadLoop();

            /**
             * Auxiliary method, to called on the internal thread loop when there is a pending timer.
             * Should sleep until the timer expiration time or until notifyThreadLoop is called.
             */
            void handleTimer(InternalTimerInfo const& closestTimer);

            /**
             * Auxiliary method, to called on the internal thread loop when there are no pending timers.
             * Should wait until notifyThreadLoop is called.
             */
            void handleNoTimer(unsigned int numberOfActiveTimers);

            /**
             * Auxiliary method, to called when (or after, since we don't have real time requirements) a timer expires.
             * Will print a description of the timer and invoke the callback.
             */
            void handleExpiredTimer(InternalTimerInfo const& timer);

            std::vector<std::weak_ptr<TimerCallbacks>> myCallbacks;
            std::condition_variable myConditionVariable;
            mutable std::mutex myDataMutex;
            std::vector<InternalTimerInfo> myTimers;
            std::thread myThread;
            Id myCurrentId; ///< Holds the last used timer ID, is used to generate sequential unique IDs for the timers that are created.
            bool myExitRequested;
    };
}

#endif
