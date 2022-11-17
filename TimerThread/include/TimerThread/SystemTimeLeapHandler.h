#ifndef SYSTEMTIMELEAPHANDLER_H
#define SYSTEMTIMELEAPHANDLER_H

#include "OsEncap/OsThread.h"
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>


class SystemTimeLeapHandler : public OsThread
{
    public:
        SystemTimeLeapHandler();
        virtual ~SystemTimeLeapHandler();
        SystemTimeLeapHandler(const SystemTimeLeapHandler&) = delete;
        SystemTimeLeapHandler& operator= (const SystemTimeLeapHandler&) = delete;

    private:
        virtual void handleSystemTimeLeap() = 0;
        virtual void handleShutdown() = 0;

        virtual void Run() override;

        void setTimer();
        void abortTimer();
        void waitForSystemTimeChange();

        // syncronization for thread startup and shutdown
        boost::mutex myThreadStateMutex;
        boost::condition_variable myThreadStateCondition;
        bool myIsRunning;
        bool myIsShutdownRequested;

        int myTimerFd;
};

#endif
