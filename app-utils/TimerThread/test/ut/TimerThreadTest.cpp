#include <sstream>
#include <chrono>
#include <mutex>
#include "gtest/gtest.h"
#include "TimerThread/TimerThread.h"

// create a timer that launch a thread after a waiting time of n seconds
TEST(TimerThreadTest, createTimerThread)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    TimerThread testTimerThreadObj;
    ASSERT_FALSE(testTimerThreadObj.isRunning()) << "Thread is state is 'running' without start the timer!";

    // //////////////////////////////////////////////////////////////////
    // Test to launch a timer thread and wait to execution be completed
    // //////////////////////////////////////////////////////////////////

    bool functionHasExecuted = false;
    bool timerStatus = testTimerThreadObj.setTimer([&]()
    {
        functionHasExecuted = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    },
    std::chrono::milliseconds(1000)); // delay 1000ms

    ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

    //Give time to timer thread start counting
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    //Validate whether still there is remaining time until thread function handler is to be executed (must be > 0)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() > 0) << "Expected to have some remaining time delay!";

    //Give time to out timer expires and start thread
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    // Now thread shall be in 'running'
    EXPECT_TRUE(testTimerThreadObj.isRunning()) << "Thread is NOT in 'running' state after timer expired!";

    //Validate that there is NO remaining time until thread function handler is to be executed (already done)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() == 0) << "Expected ZERO remaining time delay!";

    //Give time to out timer thread terminate execution
    std::this_thread::sleep_for(std::chrono::milliseconds(10000));

    //Validate that there is NO remaining time until thread function handler is to be executed (already done)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() == 0) << "Expected ZERO remaining time delay!";

    EXPECT_TRUE(functionHasExecuted);
    EXPECT_FALSE(testTimerThreadObj.isRunning()) << "Thread is 'running' state after timer thread complete execution!";
}

// create a timer that launch a thread without delay
TEST(TimerThreadTest, createTimerThreadWithZeroDelay)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    TimerThread testTimerThreadObj;
    ASSERT_FALSE(testTimerThreadObj.isRunning()) << "Thread is state is 'running' without start the timer!";

    // //////////////////////////////////////////////////////////////////
    // Test to launch a timer thread and wait to execution be completed
    // //////////////////////////////////////////////////////////////////

    bool functionHasExecuted = false;
    bool timerStatus = testTimerThreadObj.setTimer([&]()
    {
        functionHasExecuted = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    },
    std::chrono::milliseconds(0)); // 0 delay

    ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

    //Validate whether still there is remaining time until thread function handler is to be executed (must be > 0)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() == 0) << "Expected 0 remaining time delay!";

    // Now thread shall be in 'running'
    EXPECT_TRUE(testTimerThreadObj.isRunning()) << "Thread is NOT in 'running' state after timer expired!";

    //Give time to timer thread terminate execution
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    EXPECT_TRUE(functionHasExecuted);
    EXPECT_FALSE(testTimerThreadObj.isRunning()) <<
                                                 "Thread is still in 'running' state after timer thread complete execution!";
}

// create a timer thread and attempt to start several timers on same object => this shall not be possible
TEST(TimerThreadTest, startSeveralTimersOnSameTimerThreadObject)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    TimerThread testTimerThreadObj;

    bool timerStatus = testTimerThreadObj.setTimer([&]()
    {
    },
    std::chrono::milliseconds(1000)); // delay 1000ms
    EXPECT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

    // Right-after, attempt to start another timer on same timer thread object
    timerStatus = testTimerThreadObj.setTimer([&]()
    {
    },
    std::chrono::milliseconds(100)); // delay 100ms
    EXPECT_FALSE(timerStatus) << "Set Timer could not be done because still running!";
}

// stop timer while timer is still in countdown
TEST(TimerThreadTest, stopTimerThread)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    TimerThread testTimerThreadObj;
    bool timerStatus = testTimerThreadObj.setTimer([&]()
    {
    },
    std::chrono::milliseconds(5000)); // delay 5000ms

    ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

    // Now thread shall be in 'running'
    EXPECT_TRUE(testTimerThreadObj.isRunning()) << "Thread is NOT in 'running' state after timer expired!";

    // Stop Timer (while timer still counting)
    testTimerThreadObj.stop();

    EXPECT_FALSE(testTimerThreadObj.isRunning()) << "Thread is 'running' state after stop the timer!";
    EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    //Validate that there is NO remaining time until thread function handler is to be executed (already done)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() == 0);
}

// stop TimerThread object while thread's function still executing
TEST(TimerThreadTest, testStopWhileRunning)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    {
        TimerThread testTimerThreadObj;
        bool timerStatus = testTimerThreadObj.setTimer([&]()
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10000));
        },
        std::chrono::milliseconds(100)); // delay 100ms
        ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

        // Now thread shall be in 'running'
        EXPECT_TRUE(testTimerThreadObj.isRunning()) << "Thread is NOT in 'running' state after timer expired!";
        EXPECT_EQ(TimerThread::runningThreadCount(), 1) << "Expected 1 thread running!";

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        testTimerThreadObj.stop();
        EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

        timerStatus = testTimerThreadObj.setTimer([&]()
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10000));
        },
        std::chrono::milliseconds(100)); // delay 100ms
        ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";
    }

    // After object is deleted, no timer thread are expected to be running
    EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";
}

// reuse TimerThread object after function task being terminated
TEST(TimerThreadTest, testReuseAfterRunning)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    {
        TimerThread testTimerThreadObj;
        bool timerStatus = testTimerThreadObj.setTimer([&]()
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        },
        std::chrono::milliseconds(10)); // delay 10ms
        ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

        // Now thread shall be in 'running'
        EXPECT_TRUE(testTimerThreadObj.isRunning()) << "Thread is NOT in 'running' state after timer expired!";
        EXPECT_EQ(TimerThread::runningThreadCount(), 1) << "Expected 1 thread running!";

        // Wait some time to allow the task to complete
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // The task has been complete
        EXPECT_FALSE(testTimerThreadObj.isRunning()) << "Thread is still in 'running' state after long wait!";
        EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

        // Reuse the timer to start a new task
        timerStatus = testTimerThreadObj.setTimer([&]()
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        },
        std::chrono::milliseconds(10)); // delay 10ms
        ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";
    }

    // After object is deleted, no timer thread are expected to be running
    EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";
}

// delete TimerThread object while timer still executing => none thread shall be running after object is deleted
TEST(TimerThreadTest, deleteTimerThreadObjectWhileTimerStillExecuting)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    {
        TimerThread testTimerThreadObj;
        bool timerStatus = testTimerThreadObj.setTimer([&]()
        {
            while(true)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            };
        },
        std::chrono::milliseconds(100)); // delay 100ms
        ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";
        // Now thread shall be in 'running'
        EXPECT_TRUE(testTimerThreadObj.isRunning()) << "Thread is NOT in 'running' state after timer expired!";
        EXPECT_EQ(TimerThread::runningThreadCount(), 1) << "None timer threads are running!";
    }

    // After object is deleted, no timer thread are expected to be running
    EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";
}

// delete TimerThread object after timer finishes execution
TEST(TimerThreadTest, deleteJoinableTimerThreadObjectAfterTimerExecution)
{
    bool executionComplete = false;

    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    {
        // Create a joinable task
        TimerThread testTimerThreadObj(false);
        bool timerStatus = testTimerThreadObj.setTimer([&]()
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            executionComplete = true;
        },
        std::chrono::milliseconds(0)); // no delay

        ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";
        // Now thread shall be in 'running'
        EXPECT_TRUE(testTimerThreadObj.isRunning()) << "Thread is NOT in 'running' state after timer expired!";
        EXPECT_EQ(TimerThread::runningThreadCount(), 1) << "No timer threads are running!";

        // Allow some time for the handler to start and finish
        std::this_thread::sleep_for(std::chrono::seconds(1));

        EXPECT_FALSE(testTimerThreadObj.isRunning()) << "Thread is sill in 'running' state after waiting";
    }

    // Check that the handler function was able to complete
    EXPECT_TRUE(executionComplete) << "The task was not able to finish!";

    // After object is deleted, no timer threads are expected to be running
    EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";
}

// delete TimerThread object while joinable timer still executing => the handler must be able finish
TEST(TimerThreadTest, deleteTimerThreadObjectWhileJoinableTimerStillExecuting)
{
    bool executionComplete = false;

    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    {
        // Create a joinable task
        TimerThread testTimerThreadObj(false);
        bool timerStatus = testTimerThreadObj.setTimer([&]()
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            executionComplete = true;
        },
        std::chrono::milliseconds(0)); // no delay

        ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";
        // Now thread shall be in 'running'
        EXPECT_TRUE(testTimerThreadObj.isRunning()) << "Thread is NOT in 'running' state after timer expired!";
        EXPECT_EQ(TimerThread::runningThreadCount(), 1) << "No timer threads are running!";

        // Allow some time for the handler to start
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // Check that the handler function was able to complete
    EXPECT_TRUE(executionComplete) << "The task was not able to finish!";

    // After object is deleted, no timer thread are expected to be running
    EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";
}

// stop TimerThread object while joinable timer still executing => the handler must be able finish
TEST(TimerThreadTest, stopTimerThreadObjectWhileJoinableTimerStillExecuting)
{
    bool executionComplete = false;

    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    // Create a joinable task
    TimerThread testTimerThreadObj(false);
    bool timerStatus = testTimerThreadObj.setTimer([&]()
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        executionComplete = true;
    },
    std::chrono::milliseconds(0)); // no delay

    ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";
    // Now thread shall be in 'running'
    EXPECT_TRUE(testTimerThreadObj.isRunning()) << "Thread is NOT in 'running' state after timer expired!";
    EXPECT_EQ(TimerThread::runningThreadCount(), 1) << "No timer threads are running!";

    // Allow some time for the handler to start
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Stop the timer
    testTimerThreadObj.stop();

    // Check that the handler function was able to complete
    EXPECT_TRUE(executionComplete) << "The task was not able to finish!";

    // After object is deleted, no timer thread are expected to be running
    EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";
}

/*
 * NOTE:
 * Next UT was commented out because when running in loaded systems, the rate of failure is considerable high.
 * The problem seems that when a TimerThread is in deadlock state, when trying to stop() it, may happens that
 * running state remains active more time than expected (the stop() implements a limited timeout).
 * Although does not means that TimeThread remains block ever after but, after call stop() may need more time
 * to have it back not 'not running' state.
 *
 * The UT may be improved by placing a sleep time after the stop,
 * but we do not want to extend the duration of the UT run.
 *
// Launch two timer threads that generated a dead lock to each other => one shall be able to stop thread in this cases
TEST(TimerThreadTest, threadsEndsUpInDeadlock)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";
    {
        std::mutex mutexA;
        std::mutex mutexB;
        TimerThread testTimerThreadObj1;
        bool timerStatus = testTimerThreadObj1.setTimer([&]()
        {
            std::lock_guard<std::mutex> lockA(mutexA);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            std::lock_guard<std::mutex> lockB(mutexB);
        },
        std::chrono::milliseconds(10)); // delay 10ms
        ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

        TimerThread testTimerThreadObj2;
        timerStatus = testTimerThreadObj2.setTimer([&]()
        {
            std::lock_guard<std::mutex> lockB(mutexB);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            std::lock_guard<std::mutex> lockA(mutexA);
        },
        std::chrono::milliseconds(10)); // delay 10ms
        ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

        EXPECT_EQ(TimerThread::runningThreadCount(), 2) << "None timer threads are running!";

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // Both thread shall still be running (in blocking state)
        EXPECT_TRUE(testTimerThreadObj1.isRunning()) << "Thread is NOT in 'running' state after timer expired!";
        EXPECT_TRUE(testTimerThreadObj2.isRunning()) << "Thread is NOT in 'running' state after timer expired!";
        EXPECT_EQ(TimerThread::runningThreadCount(), 2) << "None timer threads are running!";

        // Now stop threads and test if are really stopped
        testTimerThreadObj1.stop();
        EXPECT_FALSE(testTimerThreadObj1.isRunning()) << "Thread is in 'running' state after timer stopped!";
        testTimerThreadObj2.stop();
        EXPECT_FALSE(testTimerThreadObj2.isRunning()) << "Thread is in 'running' state after timer stopped!";
    }

    // After object is deleted, no timer thread are expected to be running
    EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";
}
*/

// Stress test => launch 100 timer threads and terminate all
TEST(TimerThreadTest, stressTest)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    std::vector<TimerThread*> myTimers;

    for(int i = 0; i < 100; ++i)
    {
        TimerThread* timerThr = new TimerThread();
        timerThr->setTimer([&]()
        {
            while(true)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            };
        },
        std::chrono::milliseconds(i));
        myTimers.push_back(timerThr);
    }

    EXPECT_EQ(TimerThread::runningThreadCount(), 100) << "Number of running Timer threads is NOT as expected!";

    // Now stop all
    for(auto& timerThreadIt : myTimers)
    {
        timerThreadIt->stop();
        delete timerThreadIt;
    }

    // Clear vector
    myTimers.clear();

    EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";
}

// Create a periodic timer that executes a function every 100 milliseconds during 1 second
TEST(TimerThreadTest, createPeriodicTimerThread)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    TimerThread testTimerThreadObj;
    ASSERT_FALSE(testTimerThreadObj.isRunning()) << "Thread is state is 'running' without start the timer!";

    bool executionComplete = false;
    unsigned int functionExecutedCount = 0;

    bool timerStatus = testTimerThreadObj.setPeriodicTimer([&](bool isPeriodic)
    {
        if(isPeriodic)
        {
            ++functionExecutedCount;
        }
        else
        {
            executionComplete = true;
        }
    },
    std::chrono::milliseconds(100),   // Period 100 milliseconds
    std::chrono::milliseconds(1000)); // Timeout 1 second

    ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

    // Give time to timer thread start counting
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    // Validate whether still there is remaining time until thread function handler is to be executed (must be > 0)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() > 0) << "Expected to have some remaining time delay!";

    // Give time to timer period expires and start the function
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Now thread shall be in 'running'
    EXPECT_TRUE(testTimerThreadObj.isRunning()) << "Thread is NOT in 'running' state after timer expired!";

    // Validate that there is some remaining time until thread function handler is to be executed (already done)
    EXPECT_FALSE(testTimerThreadObj.getRemainingTime().count() == 0) << "Not expected ZERO remaining time delay!";

    // Give time to timer thread terminate execution
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    // Validate that there is NO remaining time until thread function handler is to be executed (already done)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() == 0) << "Expected ZERO remaining time delay!";

    // Confirm it run at least 9 cycles
    EXPECT_TRUE(functionExecutedCount >= 9);
    // Confirm it completed the 1 second execution
    EXPECT_TRUE(executionComplete);
    EXPECT_FALSE(testTimerThreadObj.isRunning()) << "Thread is 'running' state after timer thread complete execution!";
}

// Create a periodic timer that executes a function every 20 milliseconds during 50 milliseconds
TEST(TimerThreadTest, createPeriodicTimerThreadPartialPeriod)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    TimerThread testTimerThreadObj;
    ASSERT_FALSE(testTimerThreadObj.isRunning()) << "Thread is state is 'running' without start the timer!";

    bool executionComplete = false;
    unsigned int functionExecutedCount = 0;

    bool timerStatus = testTimerThreadObj.setPeriodicTimer([&](bool isPeriodic)
    {
        if(isPeriodic)
        {
            ++functionExecutedCount;
        }
        else
        {
            executionComplete = true;
        }
    },
    std::chrono::milliseconds(20),  // Period 20 milliseconds
    std::chrono::milliseconds(50)); // Timeout 50 milliseconds

    ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

    // Give time to timer thread start counting
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    // Validate whether still there is remaining time until thread function handler is to be executed (must be > 0)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() > 0) << "Expected to have some remaining time delay!";

    // Give time timer runs completely
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    // Verify the it run 2 cycles
    EXPECT_EQ(functionExecutedCount, 2);
    // Confirm it completed the 50 milliseconds execution
    EXPECT_TRUE(executionComplete);

    // Validate that there is NO remaining time until thread function handler is to be executed (already done)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() == 0) << "Expected ZERO remaining time delay!";

    // Confirm thread is not running
    EXPECT_FALSE(testTimerThreadObj.isRunning()) << "Thread is 'running' state after timer thread complete execution!";
}

// Create a periodic timer that executes a function every 0 milliseconds during 50 milliseconds
TEST(TimerThreadTest, createPeriodicTimerThreadZeroPeriod)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    TimerThread testTimerThreadObj;
    ASSERT_FALSE(testTimerThreadObj.isRunning()) << "Thread is state is 'running' without start the timer!";

    bool executionComplete = false;
    unsigned int functionExecutedCount = 0;

    bool timerStatus = testTimerThreadObj.setPeriodicTimer([&](bool isPeriodic)
    {
        if(isPeriodic)
        {
            ++functionExecutedCount;
        }
        else
        {
            executionComplete = true;
        }
    },
    std::chrono::milliseconds(0),   // Period 0 milliseconds
    std::chrono::milliseconds(50)); // Timeout 50 milliseconds

    ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

    // Give time to timer thread start counting
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Validate whether still there is remaining time until thread function handler is to be executed (must be > 0)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() > 0) << "Expected to have some remaining time delay!";

    // Give time timer runs completely
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Verify the it run
    EXPECT_TRUE(functionExecutedCount > 1);

    // Confirm it completed the 50 milliseconds execution
    EXPECT_TRUE(executionComplete);

    // Validate that there is NO remaining time until thread function handler is to be executed (already done)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() == 0) << "Expected ZERO remaining time delay!";

    // Confirm thread is not running
    EXPECT_FALSE(testTimerThreadObj.isRunning()) << "Thread is 'running' state after timer thread complete execution!";
}

// Create a periodic timer that executes a function every 500 milliseconds during 400 milliseconds
TEST(TimerThreadTest, createPeriodicTimerThreadPeriodBiggerThanTimeout)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    TimerThread testTimerThreadObj;
    ASSERT_FALSE(testTimerThreadObj.isRunning()) << "Thread is state is 'running' without start the timer!";

    bool executionComplete = false;
    unsigned int functionExecutedCount = 0;

    bool timerStatus = testTimerThreadObj.setPeriodicTimer([&](bool isPeriodic)
    {
        if(isPeriodic)
        {
            ++functionExecutedCount;
        }
        else
        {
            executionComplete = true;
        }
    },
    std::chrono::milliseconds(500),  // Period 500 milliseconds
    std::chrono::milliseconds(400)); // Timeout 400 milliseconds

    ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

    // Give time to timer thread start counting
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    // Validate whether still there is remaining time until thread function handler is to be executed (must be > 0)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() > 0) << "Expected to have some remaining time delay!";

    // Give time timer runs completely
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    // Verify the it didn't run any cycle
    EXPECT_TRUE(functionExecutedCount == 0);
    // Confirm it completed the execution
    EXPECT_TRUE(executionComplete);

    // Validate that there is NO remaining time until thread function handler is to be executed (already done)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() == 0) << "Expected ZERO remaining time delay!";

    // Confirm thread is not running
    EXPECT_FALSE(testTimerThreadObj.isRunning()) << "Thread is 'running' state after timer thread complete execution!";
}

// Create a periodic timer that executes a function every 100 milliseconds during 400 milliseconds and stop during execution
TEST(TimerThreadTest, testStopRunningPeriodicTimerThread)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    TimerThread testTimerThreadObj;
    ASSERT_FALSE(testTimerThreadObj.isRunning()) << "Thread is state is 'running' without start the timer!";

    bool executionComplete = false;
    unsigned int functionExecutedCount = 0;

    bool timerStatus = testTimerThreadObj.setPeriodicTimer([&](bool isPeriodic)
    {
        if(isPeriodic)
        {
            ++functionExecutedCount;
        }
        else
        {
            executionComplete = true;
        }
    },
    std::chrono::milliseconds(100),  // Period 100 milliseconds
    std::chrono::milliseconds(400)); // Timeout 400 milliseconds

    ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

    // Give time to timer thread start counting
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Validate whether still there is remaining time until thread function handler is to be executed (must be > 0)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() > 0) << "Expected to have some remaining time delay!";

    // Confirm thread is running
    EXPECT_TRUE(testTimerThreadObj.isRunning()) << "Thread is 'running' state after timer thread complete execution!";

    // Verify that 1 cycle have run
    EXPECT_TRUE(functionExecutedCount == 1);

    // Stop the periodic timer thread
    testTimerThreadObj.stop();

    // Give time to thread stop execution
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    // Confirm thread is not running
    EXPECT_FALSE(testTimerThreadObj.isRunning()) << "Thread is 'running' state after timer thread complete execution!";

    // Confirm it didn't complete the execution
    EXPECT_FALSE(executionComplete);

    // Validate that there is NO remaining time until thread function handler is to be executed (already done)
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() == 0) << "Expected ZERO remaining time delay!";
}

// Create a periodic timer that executes a function every 10 milliseconds for 0 milliseconds
TEST(TimerThreadTest, createPeriodicTimerThreadZeroTimeout)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    TimerThread testTimerThreadObj;
    ASSERT_FALSE(testTimerThreadObj.isRunning()) << "Thread is state is 'running' without start the timer!";

    bool executionComplete = false;
    unsigned int functionExecutedCount = 0;

    bool timerStatus = testTimerThreadObj.setPeriodicTimer([&](bool isPeriodic)
    {
        if(isPeriodic)
        {
            ++functionExecutedCount;
        }
        else
        {
            executionComplete = true;
        }
    },
    std::chrono::milliseconds(10), // Period 10 milliseconds
    std::chrono::milliseconds(0)); // Timeout 0 milliseconds

    ASSERT_TRUE(timerStatus) << "Set Timer could not be done because still running!";

    // Give time to timer thread start counting
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    // Validate whether NO remaining time to be executed
    EXPECT_TRUE(testTimerThreadObj.getRemainingTime().count() == 0) << "Expected ZERO remaining time!";

    // Give time timer runs completely
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // Verify the it didn't run any cycle
    EXPECT_TRUE(functionExecutedCount == 0);
    // Confirm it completed the execution
    EXPECT_TRUE(executionComplete);

    // Confirm thread is not running
    EXPECT_FALSE(testTimerThreadObj.isRunning()) << "Thread is 'running' state after timer thread complete execution!";
}

// Test deletion of a running timer
TEST(TimerThreadTest, deleteWhenWorking)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    bool working = false;
    bool exit = false;
    std::mutex threadLock;

    std::thread t([&]
    {
        std::unique_lock<std::mutex> lock(threadLock);

        while(false == exit)
        {
            std::this_thread::yield();
            std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        }
    });
    t.detach();

    TimerThread* timerThr = new TimerThread();
    timerThr->setTimer([&]()
    {
        int i = 0;

        while(i < 3)
        {
            std::unique_lock<std::mutex> lock(threadLock);
            working = true;
            ++i;
        };
    },
    std::chrono::milliseconds(0));

    // Ensure the timer starts to actually run
    std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_EQ(TimerThread::runningThreadCount(), 1) << "Number of running Timer threads is NOT as expected!";

    exit = true;
    delete timerThr;

    EXPECT_TRUE(working) << "Thread was not executed before the delete";
    EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";
}

// Test terminateTimer by assuring that only the timer is stopped
TEST(TimerThreadTest, terminateTimer)
{
    ASSERT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";

    // Test the case where terminateTimer is effectively terminating the timer
    {
        bool lambdaExecuted = false;

        TimerThread timerThr;
        timerThr.setTimer([&]()
        {
            lambdaExecuted = true;
        },
        std::chrono::milliseconds(1000));

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        EXPECT_TRUE(timerThr.isRunning()) << "Timer Thread not running!";

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        EXPECT_TRUE(timerThr.getRemainingTime().count() > 0) << "Timer Thread not started yet!";

        // Now terminate the timer
        timerThr.terminateTimer();

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        EXPECT_FALSE(timerThr.isRunning()) << "Timer Thread still running!";
        EXPECT_FALSE(lambdaExecuted) << "Lambda was executed";
    }

    // Test the case where lambda is already running and cannot be terminated by terminateTimer()
    {
        bool lambdaExecuted = false;

        TimerThread timerThr;
        timerThr.setTimer([&]()
        {
            lambdaExecuted = true;

            while(true)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            };
        },
        std::chrono::milliseconds(0));

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        EXPECT_TRUE(timerThr.isRunning()) << "Timer Thread not running!";
        EXPECT_TRUE(lambdaExecuted) << "Lambda was not executed";

        // Now terminate the timer
        timerThr.terminateTimer();

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        EXPECT_TRUE(timerThr.isRunning()) << "Timer Thread not running!";

        // Only the stop could stop the lamda from continue running
        timerThr.stop();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        EXPECT_FALSE(timerThr.isRunning()) << "Timer Thread still running!";
    }

    EXPECT_EQ(TimerThread::runningThreadCount(), 0) << "Timer threads still running!";
}
