#ifndef TASKRUNNER_H
#define TASKRUNNER_H

#include "Task.h"

namespace appUtils
{
    typedef unsigned int TaskId;

    class TaskRunner
    {
        public:
            virtual TaskId queue(std::unique_ptr<Task> task) = 0;

            /**
             * Implementation of the task runner consumer loop.
             * Typically, this is intended to run in its own thread.
             *
             * But, for unit testing purposes, if the synchronousFlush attribute is set,
             * This method will run through the current queued tasks, execute them all synchronously
             * and then return (instead of waiting for more tasks).
             *
             * @param synchronousFlush If set to true, execute all tasks synchronously and return.
             */
            virtual void consumerThreadLoop(bool synchronousFlush) = 0;

            virtual void requestExit() = 0;
    };

    TaskRunner& taskRunner();
}

#endif
