#ifndef TIMERMOCK_H
#define TIMERMOCK_H

#include "gmock/gmock.h"
#include "TimerInterface.h"

class TimerMock: public appUtils::TimerInterface
{
    public:
        ~TimerMock() override = default;
        MOCK_METHOD(Id, startTimer, (std::string const&, std::chrono::seconds), (override));
        MOCK_METHOD(void, cancelTimer, (Id), (override));
        MOCK_METHOD(std::vector<TimerInfo>, getActiveTimers, (), (const, override));
        MOCK_METHOD(void, addTimerClient, (std::weak_ptr<appUtils::TimerCallbacks>), (override));
};

#endif
