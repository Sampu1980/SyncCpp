#include "TimerThread/TimerThread.h"

unsigned int TimerThread::myRunningThreadCounter = 0;

TimerThread::TimerThread()
    : myThreadId(global_invalid_thread_id)
    , myDoShutdown(false)
    , myIsRunning(false)
    , myEnabled(true)
    , myHandlerCancelable(true)
    , myLastConfigDelay(0)
{
}

TimerThread::TimerThread(bool handlerCancelable)
    : myThreadId(global_invalid_thread_id)
    , myDoShutdown(false)
    , myIsRunning(false)
    , myEnabled(true)
    , myHandlerCancelable(handlerCancelable)
    , myLastConfigDelay(0)
{
}

TimerThread::TimerThread(TimerThread&& obj)
    : myThreadId(obj.myThreadId.load())
    , myThread(std::move(obj.myThread))
    , myDoShutdown(obj.myDoShutdown)
    , myIsRunning(obj.myIsRunning)
    , myEnabled(obj.myEnabled)
    , myHandlerCancelable(obj.myHandlerCancelable)
    , myLastConfigDelay(obj.myLastConfigDelay)
{
}

TimerThread::~TimerThread()
{
    setEnabled(false);
    stop();

    // Guarantee the join step if the thread is joinable (regardless of the previous calls)
    if(myThread.joinable())
    {
        myThread.join();
    }
    else
    {
        // If thread is not joinable wait for it to signal it has ended
        if(myFutureThreadEnded.valid())
        {
            myFutureThreadEnded.wait();
        }
    }
}

bool TimerThread::operator==(const TimerThread& rhs) const
{
    return (myDoShutdown == rhs.myDoShutdown &&
            myIsRunning  == rhs.myIsRunning  &&
            myThreadId   == rhs.myThreadId   &&
            myEnabled    == rhs.myEnabled    &&
            myHandlerCancelable == rhs.myHandlerCancelable   &&
            myLastConfigDelay   == rhs.myLastConfigDelay);
}

bool TimerThread::operator!=(const TimerThread& rhs) const
{
    return !operator==(rhs);
}

TimerThread& TimerThread::operator=(TimerThread&& rhs)
{
    if(rhs != *this)
    {
        myDoShutdown        = rhs.myDoShutdown;
        myIsRunning         = rhs.myIsRunning;
        myThreadId          = rhs.myThreadId.load();
        myThread            = std::move(rhs.myThread);
        myEnabled           = rhs.myEnabled;
        myHandlerCancelable = rhs.myHandlerCancelable;
        myLastConfigDelay   = rhs.myLastConfigDelay;
    }

    return *this;
}

void TimerThread::taskCleanUpHandlerWrapper(void* parms)
{
    ((TimerThread*)parms)->taskCleanUpHandler();
}

void TimerThread::taskCleanUpHandler()
{
    // Declare thread in not running
    myThreadId  = global_invalid_thread_id;
    myIsRunning = false;
    myRunningThreadCounter--;
    myDoShutdown = false;

    // Force delay to be expired, reset configuration delay
    myLastConfigDelay = std::chrono::milliseconds::zero();
}

bool TimerThread::isRunning() const
{
    return myIsRunning;
}

void TimerThread::stop()
{
    // First - Try stop thread by its shutdown primitive
    try
    {
        boost::unique_lock<boost::mutex> lock(myDoShutdownMutex);
        myDoShutdown = true;
    }
    catch(const boost::lock_error& ex)
    {
        myDoShutdown = true;
    }

    // It is only possible to stop a thread if:
    // * Thread is still running
    // * Is not the thread itself trying to stop it
    if(myIsRunning && (global_invalid_thread_id != myThreadId) && (pthread_self() != myThreadId))
    {
        myDoShutdownConditionVariable.notify_all(); // Signal all to shutdown

        if(myHandlerCancelable)
        {
            // Wait some moment to give time thread stops and execute clean-up routines
            std::this_thread::sleep_for(std::chrono::milliseconds(1));

            // TODO NC: Current implementation do not cover cases where TimerThread lambda is already running and
            //          give time for it to finish.
            // Possible solutions:
            // a) Evaluate the possibility to use a synchronous solution by creating a joinable thread instead of detach it.
            //    NOTE/CAUTION: - Before arm new timer we MUST join the previous thread execution.
            //                  - At TimerThread destructor we need to join the thread object
            //                  (https://en.cppreference.com/w/cpp/thread/thread/~thread)
            // b) Use synchronization flag (e.g. std::promise/future) to indicate the associated thread has finished.
            //    Altough, if we want to keep the forcible way to stop a thread, a timeout should be used for it to finish.
            // c) Drop the ability to cancel the thread (cases where thread is unmanageable/blocked/dead_lock/etc) and simplify implementation
            //    using std::async

            // Second - if still running force interruption of the thread
            if(myIsRunning)
            {
                if(pthread_cancel(myThreadId) != 0)
                {
                    // Give up... force to reset status variable to make TimerThread usable right-after
                    taskCleanUpHandler();
                }
                else // thread cancel was issued successfully
                {
                    // Give a first chance for CPU execute pthread cancellation clean-up handlers.
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));

                    // Cancel routine will declare that pthread is no longer running
                    // wait that cancel has been completed (with a defined timeout)
                    int timeoutCountDown = 20; // ms

                    while(myIsRunning && timeoutCountDown > 0)
                    {
                        // Give another a chance for CPU execute pthread cancellation clean-up handlers.
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        timeoutCountDown -= 1;
                    }

                    // Force delay to be expired, reset configuration delay
                    myLastConfigDelay = std::chrono::milliseconds::zero();
                }
            }
        }
    }

    // Do not execute join if the stop was called from own thread
    // That would lead to join terminating with the error: EDEADLK - deadlock detected
    if((pthread_self() != myThreadId) && myThread.joinable())
    {
        myThread.join();
    }
}

void TimerThread::terminateTimer()
{
    // First - Try stop thread by its shutdown primitive
    try
    {
        boost::unique_lock<boost::mutex> lock(myDoShutdownMutex);
        myDoShutdown = true;
    }
    catch(const boost::lock_error& ex)
    {
        myDoShutdown = true;
    }

    // It is only possible to terminate the timer if:
    // * Thread is still running
    // * Is not the thread itself trying to stop it
    if(myIsRunning && (global_invalid_thread_id != myThreadId) && (pthread_self() != myThreadId))
    {
        myDoShutdownConditionVariable.notify_all(); // Signal all to shutdown

        // In case the thread is cancelable (consequently not joinable in this implementation)
        // wait some moment to give time thread stops and execute clean-up routines
        // (for the not cancelable case join() will be called at the end of this function)
        if(myHandlerCancelable)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));

            // If still running force interruption of the thread
            if(myIsRunning)
            {
                // Cancel routine will declare that pthread is no longer running
                // wait that cancel has been completed (with a defined timeout)
                int timeoutCountDown = 20; // ms

                while(myIsRunning && timeoutCountDown > 0)
                {
                    // Give another a chance for CPU execute pthread cancellation clean-up handlers.
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    timeoutCountDown -= 1;
                }

                // Force delay to be expired, reset configuration delay
                myLastConfigDelay = std::chrono::milliseconds::zero();
            }
        }
    }

    // Do not execute join if the stop was called from own thread
    // That would lead to join terminating with the error: EDEADLK - deadlock detected
    if((pthread_self() != myThreadId) && myThread.joinable())
    {
        myThread.join();
    }
}

std::chrono::milliseconds TimerThread::getRemainingTime() const
{
    std::chrono::milliseconds ret = std::chrono::milliseconds::zero();

    // Check whether there is a delay configured (means that timer has started and still counting down)
    if(std::chrono::milliseconds::zero() != myLastConfigDelay)
    {
        std::chrono::milliseconds elapsedTime =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - myStartDelayCountdown);

        // Make sure remaining time is never < 0
        if(elapsedTime < myLastConfigDelay)
        {
            ret = myLastConfigDelay - elapsedTime;
        }
    }

    return ret;
}

void TimerThread::setEnabled(bool enable)
{
    myEnabled = enable;
}

unsigned int TimerThread::runningThreadCount()
{
    return myRunningThreadCounter;
}

