#ifndef TIMERINTERFACE_H
#define TIMERINTERFACE_H

#include <chrono>
#include <string>
#include <vector>
#include <memory>

namespace appUtils
{
    class TimerCallbacks;

    class TimerInterface
    {
        public:
            typedef unsigned int Id;
            static constexpr Id INVALID_ID = 0;

            struct TimerInfo
            {
                std::string humanReadableDescription;
                Id id;
                std::chrono::seconds totalDuration;
                std::chrono::seconds remainingDuration;
            };

            virtual ~TimerInterface() = default;

            virtual Id startTimer(std::string const& humanReadableDescription, std::chrono::seconds duration) = 0;
            virtual void cancelTimer(Id) = 0;
            virtual std::vector<TimerInfo> getActiveTimers() const = 0;
            virtual void addTimerClient(std::weak_ptr<TimerCallbacks> client) = 0;
    };

    class TimerCallbacks
    {
        public:
            virtual ~TimerCallbacks() = default;
            virtual bool interestedIn(TimerInterface::Id id) const = 0;
            virtual void onTimerExpired(TimerInterface::Id id, std::string const& humanReadableDescription) = 0;
            virtual std::string getTimerClientName() const = 0;
    };
}

#endif
