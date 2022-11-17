#include "app-utils/TaskRunner.h"

#include <queue>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include "fmt/core.h"
#include "logger.h"

using appUtils::TaskId;
using appUtils::Task;

class TaskRunnerImpl: public appUtils::TaskRunner
{
    public:
        TaskRunnerImpl()
            : myExitRequested(false)
            , myNextTaskId(0)
        {}

        TaskId queue(std::unique_ptr<Task> task) override
        {
            std::unique_lock<Mutex> lock(myMutex);

            unsigned int id = myNextTaskId++;
            auto const isTaskSilent = task->isTaskSilent();
            std::string const name = task->getName();
            bool const hasArguments = task->hasArguments();
            std::string const description = hasArguments ? fmt::format("{}{}", name, task->getArguments()) : name;

            if(isTaskSilent)
            {
                // Note: don't create a common string for this duplicated log message with the below one
                // It seems APP_SINFO/TRACE function parse the chars () wrongly and triggers a sig_abort
                APP_STRACE(fmt::format("add task #{} to the queue ({}) (queue size:{})", id, description, myTasks.size()));
            }
            else
            {
                APP_SINFO(fmt::format("add task #{} to the queue ({}) (queue size:{})", id, description, myTasks.size()));
            }

            myTasks.push(std::make_pair(id, std::move(task)));

            myConditionVariable.notify_all();

            return id;
        }

        void consumerThreadLoop(bool synchronousFlush) override
        {
            APP_SINFO(fmt::format("Consumer thread loop starting up."));

            while(!myExitRequested)
            {
                std::unique_lock<Mutex> lock(myMutex);

                if(myTasks.empty())
                {
                    if(synchronousFlush)
                    {
                        break;
                    }
                    else
                    {
                        APP_STRACE(fmt::format("Consumer thread waiting for more tasks ({})", myTasks.size()));
                        myConditionVariable.wait(lock);
                    }
                }

                if(!myTasks.empty())
                {
                    TaskId const id = std::get<0>(myTasks.front());
                    std::unique_ptr<Task> task = std::move(std::get<1>(myTasks.front()));
                    myTasks.pop();
                    // we already got the id+task out of the queue, release the lock so other threads can add items to the queue
                    // while this thread executes the task
                    lock.unlock();

                    std::string const name = task->getName();
                    auto const isTaskSilent = task->isTaskSilent();
                    bool const hasArguments = task->hasArguments();
                    std::string const description = hasArguments ? fmt::format("{}{}", name, task->getArguments()) : name;

                    if(isTaskSilent)
                    {
                        // Note: don't create a common string for this duplicated message with below one
                        // It seems the macro parses the chars () wrongly and trigger a sig_abort
                        APP_STRACE(fmt::format("exe task #{} ({}) (queue size:{})", id, description, myTasks.size()));
                    }
                    else
                    {
                        APP_SINFO(fmt::format("exe task #{} ({}) (queue size:{})", id, description, myTasks.size()));
                    }

                    bool success = false;

                    try
                    {
                        // execute the task
                        (*task)();

                        // if no exceptions were thrown, mark it ran successfully
                        success = true;
                    }
                    catch(std::exception const& e)
                    {
                        APP_SWARNING(fmt::format("Caught an exception({}) while executing task #{} ({})", e.what(), id, description));
                    }
                    catch(...)
                    {
                        APP_SWARNING(fmt::format("Caught an unknown exception while executing task #{} ({})", id, description));
                    }

                    if(success)
                    {
                        if(isTaskSilent)
                        {
                            // Note: don't create a common string for this duplicated message with below one
                            // It seems the macro parses the chars () wrongly and trigger a sig_abort
                            APP_STRACE(fmt::format("del task #{} ({}) (queue size:{})", id, description, myTasks.size()));
                        }
                        else
                        {
                            APP_SINFO(fmt::format("del task #{} ({}) (queue size:{})", id, description, myTasks.size()));
                        }
                    }
                }
            }
        }

        void requestExit() override
        {
            myExitRequested = true;
            myConditionVariable.notify_all();
        }

    private:
        bool myExitRequested;
        typedef boost::recursive_mutex Mutex;
        Mutex myMutex;
        boost::condition_variable_any myConditionVariable;
        std::queue<std::pair<TaskId, std::unique_ptr<Task>>> myTasks;
        TaskId myNextTaskId;
};

appUtils::TaskRunner& appUtils::taskRunner()
{
    static TaskRunnerImpl instance;
    return instance;
}
