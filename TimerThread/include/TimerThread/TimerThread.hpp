
template<typename FunctionType>
bool TimerThread::setTimer(FunctionType function, std::chrono::milliseconds delay)
{
    std::chrono::milliseconds period = delay;

    return setPeriodicTimer([ = ](bool periodic)
    {
        // Ignore eventual periodic call
        if(false == periodic)
        {
            function();
        }
    },
    ++period, // The period > timeout assures thread exits before period elapses and thus running lambda only once
    delay);
};

template<typename FunctionType>
bool TimerThread::setPeriodicTimer(FunctionType function, std::chrono::milliseconds period,
                                   std::chrono::milliseconds timeout)
{
    bool ret = false;

    if(myEnabled && false == myIsRunning)
    {
        // If join has not yet been called we need to do it before assigning a new thread
        stop();

        // Reset shutdown primitive
        myDoShutdown = false;

        // Create a promise that thread will start and get its future.
        std::promise<bool> promiseToStartThread;
        auto futureThreadStarted = promiseToStartThread.get_future();

        // Create a promise that thread will stop and get its future.
        std::promise<bool> promiseToStopThread;
        myFutureThreadEnded = promiseToStopThread.get_future();

        myThread = std::thread([ =, &promiseToStartThread, promiseToStop = std::move(promiseToStopThread)]() mutable
        {
            // Get the native underlying thread ID
            this->myThreadId = pthread_self();

            this->myIsRunning  = true;
            this->myRunningThreadCounter++;

            // Declare thread has started!
            promiseToStartThread.set_value(true);

            // When thread ends declare it stopped
            promiseToStop.set_value_at_thread_exit(true);

            // Make this thread cancelable
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
            // Enable thread deferred cancelability
            // "A cancellation request is deferred until the thread next calls
            // a function that is a cancellation point
            // (see http://man7.org/linux/man-pages/man7/pthreads.7.html)"
            pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

            // (1 indicate to execute the clean-up handler routine)
            int executeCleanupHandler = 1;

            // Add clean-up handler to current thread that will be automatically executed
            // when a thread is cancelled (using pthread_cancel).
            // Next calls to pthread_cleanup_push() and pthread_cleanup_pop() will delimit a scope of code
            // where current thread can be cancelled.
            // NOTE: On Linux, the pthread_cleanup_push() and pthread_cleanup_pop()
            //       functions are implemented as macros that expand to text containing
            //       '{' and '}', respectively.
            pthread_cleanup_push(taskCleanUpHandlerWrapper, this);

            // Snapshot requested delay and point in time when delay count-down has started
            this->myLastConfigDelay = timeout;
            this->myStartDelayCountdown = std::chrono::steady_clock::now();

            std::chrono::milliseconds delay = period;
            std::chrono::milliseconds remainingTime;

            while(remainingTime = getRemainingTime(), remainingTime > std::chrono::milliseconds::zero())
            {
                if(period > remainingTime)
                {
                    delay = remainingTime;
                }

                // temporary change to investigate GX-27260 - log exception info and abort
                boost::unique_lock<boost::mutex> lock(this->myDoShutdownMutex, boost::defer_lock);

                try
                {
                    lock.lock();
                }
                catch(const boost::lock_error& ex)
                {
                    APP_SERROR("An error occurred while trying to lock myDoShutdownMutex. Native error is: "
                               << ex.native_error() << ". Description is: " << ex.what());

                    assert(false);
                }

                if(false == this->myDoShutdownConditionVariable.wait_for(lock, boost::chrono::milliseconds(delay.count()),
                                                                         [this] {return this->myDoShutdown;}))
                {
                    // 'myDoShutdown' still evaluates to false after the delay
                    lock.unlock();
                    // Breaks the association of the associated mutex, so unlock() not called when 'lock' object is destroyed
                    lock.release();

                    // At this point, make sure myIsRunning flag has not been reset (to false)
                    // (e.g. Failure to cancel before reaching this point leads to reset TimerThread by force running TaskCleanupHandler)
                    // Execute function only if a full period have elapse
                    if(myIsRunning && delay == period)
                    {
                        function(true); // Run core function signaling a period have elapsed
                    }
                }
                else
                {
                    // 'myDoShutdown' still evaluates to false after the delay
                    lock.unlock();
                    // Breaks the association of the associated mutex, so unlock() not called when 'lock' object is destroyed
                    lock.release();
                    break;
                }
            }

            // Reset configuration delay
            this->myLastConfigDelay = std::chrono::milliseconds::zero();

            if(myIsRunning && !this->myDoShutdown)
            {
                // Run core function signaling timer expired
                function(false);
            }

            // Evaluate whether clean-up handler shall be executed, or not
            // This is to ensure the clean-up routine is not executed again
            if(pthread_self() != myThreadId || false == myIsRunning)
            {
                // Getting here hints that thread got un-handled... in such case, flag to NOT run clean-up handler
                // (e.g. if somehow stop() could not make its job, current TimerThread object will have myIsRunning=false)
                // (0 indicate to NOT execute the clean-up handler routine)
                executeCleanupHandler = 0;
            }

            // Declare the end of pthread cancellable scope;
            // (CleanupHandler, if executed, will set running state 'not running' and decrement internal 'running' counter)
            pthread_cleanup_pop(executeCleanupHandler);
        });

        // Get the native underlying thread ID
        myThreadId = myThread.native_handle();

        if(myHandlerCancelable)
        {
            // This thread is detached and will be forced to terminate when stop() is called
            myThread.detach();
        }

        ret = true;

        // Wait for the start of the thread (due to any pending OS scheduling delays)
        // NOTICE:
        // THIS DOES NOT include TO WAIT for configured timer delay!!
        // (Thread is declared as "started" before calling to wait_for the delay!)
        std::future_status status;
        unsigned char retryNr = 0;

        do
        {
            status = futureThreadStarted.wait_for(std::chrono::seconds(1));
            retryNr++;
        }
        while(status != std::future_status::ready && (retryNr < 3)); // Max. of 3 retries
    }

    return ret;
};
