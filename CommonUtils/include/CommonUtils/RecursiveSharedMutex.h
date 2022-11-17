#ifndef RECURSIVESHAREDMUTEX_H
#define RECURSIVESHAREDMUTEX_H

#include <thread>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <atomic>

/**
 * @class RecursiveSharedMutex
 * @brief This class augments the functionality of a shared mutex by adding
 * the ability to take recursive ownership both in exclusive and shared modes.
 * @note: Once mutex is active in one mode, further lock calls (lock/lock_shared)
 * will perform a recursive upon first locked mode.
 *
 * In case a thread locks the mutex in exclusive mode:
 * -> further locks (either exclusive or shared) from same thread (that already owns the mutex) will work as recursive (increment the counter);
 * -> further locks from different thread will effectively call std::shared_mutex::lock_shared(),
 *    which will cause this thread to block, waiting until the mutex, locked in exclusive mode by the first thread, is released;
 *
 * In case a thread locks the mutex in shared mode:
 * -> further locks (either exclusive or shared) from same thread (that already owns the mutex) will work as recursive (increment the counter);
 * -> further shared locks from different thread will effectively call std::shared_mutex::lock_shared(),
 *    which will NOT cause this thread to block because we're in shared_mode;
 * -> further exclusive locks from different thread will effectively call std::shared_mutex::lock(),
 *    which will cause this thread to block, waiting until the mutex, locked in shared mode by the first thread, is released;
 */
class RecursiveSharedMutex : public std::shared_timed_mutex
{
    public:
        /**
         * @brief Default constructor
         */
        RecursiveSharedMutex();

        /**
         * @brief Default destructor
         */
        ~RecursiveSharedMutex() = default;

        /**
         * @brief Locks the mutex, blocks if the mutex is not available
         */
        void lock();

        /**
         * @brief Unlocks the mutex
         */
        void unlock();

        /**
         * @brief Locks the mutex for shared ownership,
         * blocks if the mutex is not available
         */
        void lock_shared();

        /**
         * @brief Unlocks the mutex on shared ownership
         */
        void unlock_shared();

    private:
        int getRecursiveSharedCounter(std::thread::id id);
        void incrementRecursiveSharedCounter(std::thread::id id);
        void decrementRecursiveSharedCounter(std::thread::id id);
        void deleteRecursiveSharedCounter(std::thread::id id);

        std::atomic<std::thread::id> myOwnerId;
        std::atomic<int> myRecursiveExclusiveCounter;
        std::map<std::thread::id, int> mySharedRecursiveCountsMap;
        std::mutex myForSharedRecursiveCountsMapMutex;
};

#endif // RECURSIVESHAREDMUTEX_H
