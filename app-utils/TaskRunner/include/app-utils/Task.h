#ifndef TASK_H
#define TASK_H

#if __cplusplus < 201703L
#define PRE_CPP17
#include <experimental/tuple>
#endif

#include <string>
#include <memory>
#include <utility>
#include <tuple>
#include "app-utils/StringUtils.h"

namespace appUtils
{
    class Task
    {
        public:
            virtual ~Task() = default;

            virtual std::string getName() const = 0;

            virtual std::string getArguments() const = 0;

            virtual bool hasArguments() const = 0;

            virtual void operator()() = 0;

            virtual bool isTaskSilent() const = 0;
    };

    template<typename F, typename ... Args>
    class TaskWithParameters: public Task
    {
        public:
            TaskWithParameters(bool isTaskSilent, std::string name, F&& f, Args ... args)
                : myName(std::move(name)),
                  f(std::move(f)),
                  myArgs(args...),
                  myTaskSilent(isTaskSilent)
            {
                myArgumentsStr = fmt::format("({})", appUtils::to_string_join(", ", args ...));
            }

            std::string getName() const override
            {
                return myName;
            }

            std::string getArguments() const override
            {
                return myArgumentsStr;
            }

            bool hasArguments() const override
            {
                return std::tuple_size<decltype(myArgs)>::value != 0;
            }

            void operator()() override
            {
#ifdef PRE_CPP17
                using std::experimental::apply;
#else
                using std::apply;
#endif
                // invoke callable using arguments stored in the myArgs tuple
                apply(f, myArgs);
            }

            bool isTaskSilent() const override
            {
                return myTaskSilent;
            }

        private:
            std::string myName, myArgumentsStr;
            F f;
            std::tuple<Args...> myArgs;
            bool myTaskSilent;
    };

    template<typename F, typename ... Args>
    std::unique_ptr<Task> make_task(std::string const& name, F&& f, Args ... args)
    {
        return std::make_unique<TaskWithParameters<F, Args...>>(false, name, std::forward<F>(f), args ...);
    }

    template<typename F, typename ... Args>
    std::unique_ptr<Task> make_silent_task(std::string const& name, F&& f, Args ... args)
    {
        return std::make_unique<TaskWithParameters<F, Args...>>(true, name, std::forward<F>(f), args ...);
    }
}

#undef PRE_CPP17
#endif
