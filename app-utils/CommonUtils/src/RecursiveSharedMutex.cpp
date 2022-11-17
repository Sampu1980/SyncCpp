#include "CommonUtils/RecursiveSharedMutex.h"

RecursiveSharedMutex::RecursiveSharedMutex()
    : myRecursiveExclusiveCounter(0)
{
}

void RecursiveSharedMutex::lock()
{
    std::thread::id this_id = std::this_thread::get_id();

    if(getRecursiveSharedCounter(this_id) > 0)
    {
        // Current thread is already locked in shared mode;
        // In this case, instead of doing an lock in exclusive mode, perform a lock_shared
        RecursiveSharedMutex::lock_shared();
    }
    else
    {
        if(myOwnerId == this_id)
        {
            // Perform recursive locking
            myRecursiveExclusiveCounter++;
        }
        else
        {
            // Perform normal locking
            std::shared_timed_mutex::lock();
            myOwnerId = this_id;
            myRecursiveExclusiveCounter = 1;
        }
    }
}

void RecursiveSharedMutex::unlock()
{
    std::thread::id this_id = std::this_thread::get_id();

    if(myRecursiveExclusiveCounter == 0 && getRecursiveSharedCounter(this_id) > 0)
    {
        // Current thread only owns the mutex in shared mode;
        // In this case, instead of doing an unlock (exclusive mode), perform a unlock_shared
        RecursiveSharedMutex::unlock_shared();
    }
    else
    {
        // Check if the mutex is locked recursively
        if(myRecursiveExclusiveCounter > 1)
        {
            // Perform recursive unlocking
            myRecursiveExclusiveCounter--;
        }
        else
        {
            // Perform normal unlocking
            myOwnerId = std::thread::id(); // constructs an id that does not represent a thread
            myRecursiveExclusiveCounter = 0;
            std::shared_timed_mutex::unlock();
        }
    }
}

void RecursiveSharedMutex::lock_shared()
{
    std::thread::id this_id = std::this_thread::get_id();

    if(myOwnerId == this_id)
    {
        // Current thread already owns the mutex in exclusive mode;
        // further locks will be performed as recursive in same mode
        // Incrementing the exclusive recursive counter
        myRecursiveExclusiveCounter++;
    }
    else
    {
        // Check if the mutex is already locked in shared mode
        if(getRecursiveSharedCounter(this_id) > 0)
        {
            // Only increment the counter
            incrementRecursiveSharedCounter(this_id);
        }
        else
        {
            // In the first time, effectively call lock_shared
            std::shared_timed_mutex::lock_shared();
            incrementRecursiveSharedCounter(this_id);
        }
    }
}

void RecursiveSharedMutex::unlock_shared()
{
    std::thread::id this_id = std::this_thread::get_id();

    if(myOwnerId == this_id)
    {
        // Current thread already owns the mutex in exclusive mode;
        // further unlocks will be performed as recursive in same mode
        // Decrementing the exclusive recursive counter
        myRecursiveExclusiveCounter--;
    }
    else
    {
        // Check if the mutex is locked recursively
        if(getRecursiveSharedCounter(this_id) > 1)
        {
            // Only decrement the counter
            decrementRecursiveSharedCounter(this_id);
        }
        else
        {
            // When counter reaches 1, effectively call unlock_shared
            deleteRecursiveSharedCounter(this_id);
            std::shared_timed_mutex::unlock_shared();
        }
    }
}

int RecursiveSharedMutex::getRecursiveSharedCounter(std::thread::id id)
{
    int ret = 0;

    std::lock_guard<std::mutex> lock(myForSharedRecursiveCountsMapMutex);

    const auto& sharedCounterIt = mySharedRecursiveCountsMap.find(id);

    if(sharedCounterIt != mySharedRecursiveCountsMap.end())
    {
        ret = sharedCounterIt->second;
    }

    return ret;
}

void RecursiveSharedMutex::incrementRecursiveSharedCounter(std::thread::id id)
{
    std::lock_guard<std::mutex> lock(myForSharedRecursiveCountsMapMutex);
    mySharedRecursiveCountsMap[id]++;
}

void RecursiveSharedMutex::decrementRecursiveSharedCounter(std::thread::id id)
{
    std::lock_guard<std::mutex> lock(myForSharedRecursiveCountsMapMutex);
    mySharedRecursiveCountsMap[id]--;
}

void RecursiveSharedMutex::deleteRecursiveSharedCounter(std::thread::id id)
{
    std::lock_guard<std::mutex> lock(myForSharedRecursiveCountsMapMutex);
    mySharedRecursiveCountsMap.erase(id);
}
