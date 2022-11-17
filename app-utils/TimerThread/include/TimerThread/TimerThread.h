#ifndef TIMERTHREAD_H
#define TIMERTHREAD_H

#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/chrono/chrono_io.hpp>
#include <thread>
#include <future>
#include <chrono>
#include <mutex>
#include <iostream>
#include "logger.h"

const int global_invalid_thread_id = 0;

/**
 * @class TimerThread
 * @brief This class implements the capability of planning the execution of a given function
 *        The timer is started only by calling setter methods (example: setTimer)
 * @note Current implementation only allows to launch one timer at time, meaning that only one thread per TimerThread
 *       object in execution is allowed.
 * @note Multiple threads trying to control the same timer object (e.g. 2 threads execute the setTimer)
 *       causes undefined behavior
 */
class TimerThread
{
    public:
        /**
         * @brief Get the number of TimerThread objects that has a timer in execution
         * @return number of 'running' threads
         */
        static unsigned int runningThreadCount();

        /**
         * @brief Default constructor
         */
        TimerThread();

        /**
         * @brief Parameterized constructor to choose the task termination behavior
         * @param handlerCancelable true if the thread can be forced to terminate
         */
        TimerThread(bool handlerCancelable);

        /**
         * @brief Move constructor
         * @param obj timer thread to move from
         */
        TimerThread(TimerThread&& obj);

        /**
         * @brief Deleted copy constructor
         *        The copy constructor is deleted; threads are not copyable. Two TimerThread objects cannot represent the same thread of execution
         * @param obj timer thread to copy from
         */
        TimerThread(const TimerThread& obj) = delete;

        /**
         * @brief Destructor
         */
        ~TimerThread();

        /**
         * @brief Operator ==
         * @param rhs second argument of comparison
         * @return true if equal comparison; false otherwise
         */
        bool operator==(const TimerThread& rhs) const;

        /**
         * @brief operator !=
         * @param rhs second argument of comparison
         * @return true if not equal comparison; false otherwise
         */
        bool operator!=(const TimerThread& rhs) const;

        /**
         * @brief operator= Full assignment operation. Left hand side of the
         *        assignment will be a exact copy of rhs.
         * @param rhs source of assignment
         * @return reference to *this
         */
        TimerThread& operator=(TimerThread&& rhs);

        /**
         * @brief Plans one execution of a function in a given amount of time
         * @param function the function to execute
         * @param delay amount of time in milliseconds until function shall be executed
         * @return true if timer created successfully; false if other timer is already running
         * @note Method is not thread safe, if executed by multiple threads the behavior is undefined
         */
        template<typename FunctionType>
        bool setTimer(FunctionType function, std::chrono::milliseconds delay);

        /**
         * @brief Plans a periodic execution of a function in a given amount of time until defined timeout
         * @param function the function to be executed. The function must provide a bool argument so it is called
         *        with "true" in periodic calls and with "false" when timeout is reached
         * @param period amount of time in milliseconds between function execution calls
         * @param timeout amount of time in milliseconds until thread exits
         * @return true if timer created successfully; false if other timer is already running
         * @note Method is not thread safe, if executed by multiple threads the behavior is undefined
         */
        template<typename FunctionType>
        bool setPeriodicTimer(FunctionType function, std::chrono::milliseconds period, std::chrono::milliseconds timeout);

        /**
         * @brief Get timer running state
         * @return true if thread is running; false otherwise
         */
        bool isRunning() const;

        /**
         * @brief Stop the timer or the function execution (if timer already expired)
         */
        void stop();

        /**
         * @brief Stop the timer
         */
        void terminateTimer();

        /**
         * @brief Get remaining time until thread function handler will be executed
         * A value of std::chrono::milliseconds::zero means either:
         * - Timer has expired and thread function handler has been executed;
         * - Timer has never been triggered
         */
        std::chrono::milliseconds getRemainingTime() const;

        /**
         * @brief Set enable state of the timer thread object.
         *        enabled (default): normal behaviour where the new timer can be triggered using setTimer
         *        disabled         : not possible to trigger new timers (setTimer) from timer thread object
         * @param enable enable flag: true indicates enabled; false disabled
         */
        void setEnabled(bool enable);

    private:
        /// Statically count the number of timer thread objects that has a timer in execution
        static unsigned int myRunningThreadCounter;

        /// Thread shutdown condition variable
        boost::condition_variable myDoShutdownConditionVariable;

        /// The shutdown mutex
        boost::mutex myDoShutdownMutex;

        /// The thread identifier
        std::atomic<pthread_t> myThreadId;

        /// The thread object
        std::thread myThread;

        /// Thread shutdown variable
        bool myDoShutdown;

        /// Indication if the timer thread is running or not
        bool myIsRunning;

        /// Indication if the timer thread is enabled/disabled to launch more timers
        bool myEnabled;

        /// Indication that the handler can be forced to terminate
        bool myHandlerCancelable;

        /// Delay configuration that indicate how much time (in milliseconds)
        /// until thread function handler shall be executed
        /// A value of std::chrono::milliseconds::zero means either:
        /// - Delay timer has expired and thread function handler has been executed;
        /// - Delay timer has never been executed
        std::chrono::milliseconds myLastConfigDelay;

        /// Point in time when configured Delay has started to count down
        std::chrono::steady_clock::time_point myStartDelayCountdown;

        /**
         * @brief Routine to be pushed onto the top of the pthread stack of clean-up handlers.
         *  A clean-up handler is a function that is automatically executed when a thread is canceled (e.g. pthread_cancel)
         * @param parms context for the routine execution
         */
        static void taskCleanUpHandlerWrapper(void* parms);

        /**
         * @brief Method that will be called by taskCleanUpHandlerWrapper and will implement the clean-up specifics, including:
         * -> Declare thread in not running by setting myIsRunning flag;
         * -> Decrement static counter myRunningThreadCounter
         */
        void taskCleanUpHandler();

        std::future<bool> myFutureThreadEnded; ///< Future that indicates the thread has stopped
};

// Template implementation
#include "TimerThread/TimerThread.hpp"

#endif // TIMERTHREAD_H

