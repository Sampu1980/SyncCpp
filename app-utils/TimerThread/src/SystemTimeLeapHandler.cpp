#include "TimerThread/SystemTimeLeapHandler.h"
#include "logger.h"
#include <csignal>
#include <sys/timerfd.h>
#include <aio.h>

SystemTimeLeapHandler::SystemTimeLeapHandler()
    : OsThread("SystemTimeLeapHandler Thread",
               OsPublic::OS_THREAD_PRIORITY_NORMAL,
               OS_THREAD_DEFAULT_STACK_SIZE,
               false) // not joinable
    , myIsShutdownRequested(false)
    , myIsRunning(false)
{
    APP_SINFO("SystemTimeLeapHandler constructor.");

    // Create a real-time timer, i.e. one that tracks the system time
    myTimerFd = timerfd_create(CLOCK_REALTIME, 0);

    if(myTimerFd < 0)
    {
        APP_SCRITICAL("Could not create timer");
        return;
    }

    APP_SINFO("myTimerFd: " << myTimerFd);

    // Start the thread
    Start();

    // Wait for the thread to start
    boost::unique_lock<boost::mutex> threadStateLock(myThreadStateMutex);

    while(!myIsRunning)
    {
        myThreadStateCondition.wait(threadStateLock);
    }

    APP_SINFO("System time thread started!");
}

SystemTimeLeapHandler::~SystemTimeLeapHandler()
{
    APP_STRACE("SystemTimeLeapHandler destructor.");

    try
    {
        boost::unique_lock<boost::mutex> threadStateLock(myThreadStateMutex);

        myIsShutdownRequested = true;
        abortTimer();
        close(myTimerFd);

        if(myIsRunning)
        {
            // Wait for the thread to stop
            while(myIsRunning)
            {
                myThreadStateCondition.wait(threadStateLock);
            }
        }

        APP_SINFO("System time thread stopped!");
    }
    catch(const boost::lock_error& e)
    {
        APP_SERROR("Failed to lock timer or signal mutex - unable to properly stop signal handler thread.");
    }
    catch(const boost::condition_error& e)
    {
        APP_SERROR("Failed to wait for thread to stop - unable to properly stop signal handler thread.");
    }
    catch(const boost::thread_interrupted& e)
    {
        APP_SERROR("Failed to wait for thread to stop - unable to properly stop signal handler thread.");
    }
    catch(const std::runtime_error& e)
    {
        APP_SERROR("Unhandled error in SystemTimeLeapHandler shutdown: " << e.what());
    }
}

void SystemTimeLeapHandler::Run()
{
    // Signal constructing thread that we are running
    {
        boost::unique_lock<boost::mutex> threadStateLock(myThreadStateMutex);
        myIsRunning = true;
    }
    myThreadStateCondition.notify_one();

    // Arm the timer to start the loop
    try
    {
        setTimer();
    }
    catch(std::exception& err)
    {
        APP_SCRITICAL("Startup - error: " << err.what());
    }

    while(!myIsShutdownRequested)
    {
        try
        {
            waitForSystemTimeChange();

            if(!myIsShutdownRequested)
            {
                APP_SNOTICE("Discontinuous change to the system clock detected!");
                setTimer();                 ///< first re-arm the timer to make sure that no leap events can get lost
                handleSystemTimeLeap();     ///< Notify the leap
            }
        }
        catch(std::exception& err)
        {
            APP_SCRITICAL("Loop - Error: " << err.what());

            // If an error is continuously occurring, better to have the thread sleep 1 second between errors
            sleep(1);

            try
            {
                setTimer();
            }
            catch(std::exception& err)
            {
                APP_SCRITICAL("Failed to re-arm timer: " << err.what());
            }
        }
    }

    handleShutdown();

    // Signal destructing thread that thread is exiting.
    {
        boost::unique_lock<boost::mutex> threadStateLock(myThreadStateMutex);
        myIsRunning = false;
    }
    myThreadStateCondition.notify_one();
}

void SystemTimeLeapHandler::setTimer()
{
    // Set the timer to the most distant timePoint in the future, so that it
    // is never triggered unless a system-time change occurs
    time_t maxValue = std::numeric_limits<time_t>::max();
    static const struct timespec itValue = {maxValue, 0};
    static const struct timespec itInterval = {0, 0};
    static const struct itimerspec timePoint = {itInterval, itValue};

    if(timerfd_settime(myTimerFd,
                       TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
                       &timePoint,
                       NULL) < 0)
    {
        throw std::runtime_error(std::string("Could not set timer: ") + strerror(errno) + " myTimerFd: " + to_string(
                                     myTimerFd));
    }
}

void SystemTimeLeapHandler::abortTimer()
{
    static const struct timespec itValue = {0, 0};
    static const struct timespec itInterval = {0, 0};
    static const struct itimerspec timePoint = {itInterval, itValue};

    if(timerfd_settime(myTimerFd,
                       TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
                       &timePoint,
                       NULL) < 0)
    {
        throw std::runtime_error(std::string("Could not stop timer: ") + strerror(errno));
    }
}

void SystemTimeLeapHandler::waitForSystemTimeChange()
{
    uint64_t ticks;
    char* buffer = reinterpret_cast<char*>(&ticks);

    ssize_t ret;
    ssize_t position = 0;

    do
    {
        ret = read(myTimerFd, buffer + position, sizeof(ticks) - position);

        if(ret > 0)
        {
            position += ret;
        }
    }
    while(position < sizeof(ticks) && (ret >= 0 || (ret == -1 && errno == EINTR)));

    // According to the man page of TIMERFD_CREATE(2): The call to read(2) fails with the error ECANCELED if the
    //                                                 real-time clock undergoes a discontinuous change.

    if(myIsShutdownRequested || (ret == -1 && errno == ECANCELED))
    {
        return;
    }

    if(ret == -1 && errno != ECANCELED)
    {
        throw std::runtime_error("Timer read has exited in error.");
    }

    throw std::runtime_error(std::string("Timer triggered before shutdown: ") + to_string(ticks));
}
