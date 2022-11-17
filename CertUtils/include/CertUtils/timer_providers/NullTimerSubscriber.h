#ifndef PERIODICTIMERSUBSCRIBER_H
#define PERIODICTIMERSUBSCRIBER_H

#include "CertUtils/TimerSubscriber.h"
#include "logger.h"

/**
 * @brief  Implementation of Null TimerSubscriber
 */
class NullTimerSubscriber : public TimerSubscriber
{
    public:

        NullTimerSubscriber();
        NullTimerSubscriber(const NullTimerSubscriber&) = delete;               // Copy constructor
        NullTimerSubscriber& operator=(const NullTimerSubscriber&) = delete;    // Copy assignment operator

        NullTimerSubscriber(NullTimerSubscriber&&) = delete;               // Move constructor
        NullTimerSubscriber& operator=(NullTimerSubscriber&&) = delete;    // Move assignment operator

        virtual ~NullTimerSubscriber()
        {
            APP_STRACE("NullTimerSubscriber Destroyed!");
        }

        bool isCancelled() override
        {
            return true;
        }

        bool nonBlockCancel() override;

        bool cancel() override;

        bool nonBlockReset(std::uint64_t secs) override;

        bool reset(std::uint64_t secs) override;

        std::uint64_t relativeExpiresIn() override
        {
            std::string errorMsg{__FUNCTION__};
            errorMsg += ": Not supported in Null Timers";
            throw std::logic_error(errorMsg);
        }
};
#endif /* PERIODICTIMERSUBSCRIBER_H */
