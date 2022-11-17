#include "app-utils/TimerReal.h"

#include <utility>
#include <algorithm>
#include <fmt/core.h>
#include <fmt/chrono.h>
#include "app-utils/TaskRunner.h"
#include "logger.h"

using std::chrono::duration_cast;
using std::chrono::seconds;
using std::chrono::steady_clock;
using appUtils::TaskRunner;
using appUtils::make_task;

namespace appUtils
{
    TimerReal::TimerReal(std::weak_ptr<TimerCallbacks> callbacks)
        : myCurrentId(TimerInterface::INVALID_ID)
        , myExitRequested(false)
    {
        if(callbacks.use_count() > 0)
        {
            myCallbacks.emplace_back(std::move(callbacks));
        }
    }

    TimerReal::~TimerReal()
    {
        APP_SINFO("Shutting down timer.");
        myExitRequested = true;
        notifyThreadLoop();

        if(myThread.joinable())
        {
            APP_SINFO("Waiting for timer thread to shut down");
            myThread.join();
        }

        APP_SINFO("Timer has shut down.");
    }

    TimerInterface::Id TimerReal::startTimer(std::string const& humanReadableDescription,
                                             std::chrono::seconds duration)
    {
        std::unique_lock<std::mutex> lock(myDataMutex);

        InternalTimerInfo info;
        info.humanReadableDescription = humanReadableDescription;
        info.startTime = steady_clock::now();
        info.endTime = info.startTime + duration;
        info.id = ++myCurrentId;

        myTimers.push_back(info);

        std::sort(myTimers.begin(), myTimers.end());

        if(!isThreadInitialized())
        {
            initializeThread();
        }
        else
        {
            notifyThreadLoop();
        }

        return info.id;
    }

    void TimerReal::cancelTimer(TimerInterface::Id id)
    {
        std::unique_lock<std::mutex> lock(myDataMutex);

        auto pos = std::find_if(myTimers.begin(), myTimers.end(), [id](auto const & item)
        {
            return item.id == id;
        });

        if(pos != myTimers.end())
        {
            myTimers.erase(pos);
        }
        else
        {
            APP_SERROR(fmt::format("Unable to cancel timer #{}, could not find it (maybe it already expired?).", id));
        }

        notifyThreadLoop();
    }

    std::vector<TimerInterface::TimerInfo> TimerReal::getActiveTimers() const
    {

        std::vector<TimerInfo> result;

        std::unique_lock<std::mutex> lock(myDataMutex);
        auto const now = steady_clock::now();

        for(auto const& timer : myTimers)
        {
            TimerInfo info;
            info.humanReadableDescription = timer.humanReadableDescription;
            info.id = timer.id;
            info.totalDuration = duration_cast<seconds>(timer.endTime - timer.startTime);
            info.remainingDuration = duration_cast<seconds>(timer.endTime - now);
        }

        return std::vector<TimerInfo>();
    }

    void TimerReal::threadLoop()
    {
        APP_SNOTICE("Timer thread loop starting up.");

        while(!myExitRequested)
        {
            processExpiredTimers();

            boost::optional<InternalTimerInfo> closestTimer;
            unsigned int numberOfActiveTimers = 0;
            {
                std::unique_lock<std::mutex> lock(myDataMutex);
                closestTimer = selectNextTimer(lock);
            }

            if(!closestTimer)
            {
                handleNoTimer(numberOfActiveTimers);
            }
            else
            {
                handleTimer(closestTimer.get());
                // regardless of wait outcome we will go into another loop iteration (excluding if exit was requested).
                // at the top of the loop, the expired timers are checked and any callbacks are executed
            }
        }

        APP_SNOTICE("Timer thread loop complete, thread shutting down.");
    }

    void TimerReal::handleNoTimer(unsigned int numberOfActiveTimers)
    {
        if(numberOfActiveTimers == 0)
        {
            APP_STRACE("Timer has no pending requests, idling.");
        }
        else
        {
            APP_SERROR(fmt::format("Have {} active timers, but could not access them, idling.", numberOfActiveTimers));
        }

        unique_lock<mutex> lock(myDataMutex);
        myConditionVariable.wait(lock);
    }

    void TimerReal::handleTimer(InternalTimerInfo const& closestTimer)
    {
        unique_lock<mutex> lock(myDataMutex);
        auto const now = steady_clock::now();
        seconds remainingSeconds = chrono::duration_cast<seconds>(closestTimer.endTime - now);
        APP_SINFO(fmt::format("Next timer is: #{} \"{}\", T{:%T} left",
                              closestTimer.id,
                              closestTimer.humanReadableDescription,
                              remainingSeconds));

        myConditionVariable.wait_until(lock, closestTimer.endTime);
    }

    void TimerReal::processExpiredTimers()
    {
        unique_lock<mutex> lock(myDataMutex);
        auto const now = steady_clock::now();

        // note: myTimers is sorted by endTime.

        auto lastPositionToErase = myTimers.begin();
        int count = 0;

        for(auto it = myTimers.begin(); it != myTimers.end(); ++it)
        {
            if(it->endTime <= now)
            {
                ++count;
                APP_STRACE(fmt::format("Found expired timer(s), marking for deletion and invoking callback, count:{}", count));
                lastPositionToErase = it;
                handleExpiredTimer(*it);
            }
        }

        if(count != 0)
        {
            ++lastPositionToErase; // safe to increment, since last possible position to be set was one before end
            APP_STRACE(fmt::format("Erasing {} callback entries from timers", std::distance(myTimers.begin(), lastPositionToErase)));
            myTimers.erase(myTimers.begin(), lastPositionToErase);
        }
    }

    boost::optional<TimerReal::InternalTimerInfo> TimerReal::selectNextTimer(std::unique_lock<std::mutex> const&) const
    {
        boost::optional<TimerReal::InternalTimerInfo> result;

        if(!myTimers.empty())
        {
            result = myTimers.front();
        }

        return result;
    }

    bool TimerReal::isThreadInitialized() const
    {
        // if thread is not initialized, its id is default constructed.
        return myThread.get_id() != std::thread::id();
    }

    void TimerReal::initializeThread()
    {
        assert(!isThreadInitialized());

        if(!myExitRequested)
        {
            APP_STRACE("Initializing timer thread");
            myThread = std::thread(&TimerReal::threadLoop, this);
        }
    }

    void TimerReal::notifyThreadLoop()
    {
        myConditionVariable.notify_all();
    }

    void TimerReal::handleExpiredTimer(TimerReal::InternalTimerInfo const& timer)
    {
        seconds const s = duration_cast<seconds>(timer.endTime - timer.startTime);
        auto const msg = fmt::format("Timer #{} \"{}\" (T{:%T}) expired", timer.id, timer.humanReadableDescription, s);

        APP_SINFO(msg);
        auto task = make_task(msg, [callbacks = myCallbacks, id = timer.id, desc = timer.humanReadableDescription]()
        {
            for(auto const& client : callbacks)
            {
                if(auto callback = client.lock())
                {
                    if(callback->interestedIn(id))
                    {
                        APP_SINFO(fmt::format("invoking callback for \"{}\"", callback->getTimerClientName()));
                        callback->onTimerExpired(id, desc);
                    }
                }
                else
                {
                    APP_SERROR("Unable to lock weak_ptr to callbacks");
                }
            }
        });
        taskRunner().queue(std::move(task));
    }

    void TimerReal::addTimerClient(std::weak_ptr<TimerCallbacks> client)
    {
        myCallbacks.emplace_back(std::move(client));
    }

    bool TimerReal::InternalTimerInfo::operator<(TimerReal::InternalTimerInfo const& rhs) const
    {
        return std::tie(endTime, startTime, id, humanReadableDescription) <
               std::tie(rhs.endTime, rhs.startTime, rhs.id, rhs.humanReadableDescription);
    }
}