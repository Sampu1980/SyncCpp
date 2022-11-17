#include "CommonUtils/CompositeEntityEngine.h"

std::string to_string(CompositeEntityState val)
{
    static const std::vector<std::string> compositeStateNames =
    {
        "IDLE",
        "NORMAL",
        "COMPOSITE_ENTITY_PARTIAL_FAILURE",
        "COMPOSITE_ENTITY_FAILURE",
        "CUSTOM_EXPRESSION_EVALUATED_FALSE",
        "CUSTOM_EXPRESSION_EVALUATED_TRUE",
    };

    int valInt = static_cast<int>(val);
    assert(valInt >= 0 && valInt < compositeStateNames.size());
    return compositeStateNames[valInt];
}

CompositeEntityEngine::CompositeEntityEngine(CompositeEntityCallbackFunctionType compositeEntityCallbackFunction)
    : myCallbackFunction(compositeEntityCallbackFunction)
{
}

void CompositeEntityEngine::addCompositeRelation(std::shared_ptr<Key> compositeMoKey,
                                                 std::shared_ptr<Key> compositeMemberMoKey)
{
    std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

    myCompositeMembersMap[compositeMoKey][compositeMemberMoKey] = false; // Default: no failure
    myMemberOfMap[compositeMemberMoKey][compositeMoKey]; // Creates an entry in the map (if not already)

    // IDLE indicates that composite state:
    // -> is not determined yet: the first member is registered;  (or)
    // -> need to be re-evaluated: new member got registered and its failure state input is needed.
    // Calling setCompositeMemberFailureState, that is the API to inform the state of a member,
    // the output composite state will be evaluated and in case the new state mismatch the callback will be executed.
    myCompositeStateCacheMap[compositeMemberMoKey] = CompositeEntityState::IDLE;
}

void CompositeEntityEngine::deleteCompositeMember(std::shared_ptr<Key> compositeMemberMoKey)
{
    std::deque<std::shared_ptr<Key>> compositeEntityToEvaluateList;

    {
        std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

        auto searchComposite = myMemberOfMap.find(compositeMemberMoKey);

        if(searchComposite != myMemberOfMap.end())
        {
            for(const auto& it : myMemberOfMap[compositeMemberMoKey])
            {
                std::shared_ptr<Key> compositeEntity = it.first;

                MemberStateMap& compositeMembers = myCompositeMembersMap[compositeEntity];

                // Delete entry from composite members map
                compositeMembers.erase(compositeMemberMoKey);

                // Check whether composite entity still has members to state
                if(compositeMembers.size() == 0)
                {
                    // Delete composite entries
                    myCompositeMembersMap.erase(compositeEntity);
                    myCompositeStateCacheMap.erase(compositeEntity);
                }

                // Flag current iter composite entity to be re-evaluated
                compositeEntityToEvaluateList.push_back(compositeEntity);
            }

            // Delete entry MemberOf map
            myMemberOfMap.erase(compositeMemberMoKey);
        }
    }

    for(auto compositeEntityToEvaluate : compositeEntityToEvaluateList)
    {
        // Re-evaluate composite condition state
        evaluateCompositeState(compositeEntityToEvaluate);
    }
}

void CompositeEntityEngine::deleteCompositeMember(std::shared_ptr<Key> compositeMoKey,
                                                  std::shared_ptr<Key> compositeMemberMoKey)
{
    std::deque<std::shared_ptr<Key>> compositeEntityToEvaluateList;

    auto searchComposite = myCompositeMembersMap.find(compositeMoKey);

    if(searchComposite != myCompositeMembersMap.end())
    {
        std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

        auto searchCompositeMember = myMemberOfMap.find(compositeMemberMoKey);

        if(searchCompositeMember != myMemberOfMap.end())
        {
            for(const auto& it : myMemberOfMap[compositeMemberMoKey])
            {
                // Only delete if the keys match
                if(*compositeMoKey == *it.first)
                {
                    // Delete entry from composite members map
                    searchComposite->second.erase(compositeMemberMoKey);

                    // Check whether composite entity still has members
                    if(searchComposite->second.size() == 0)
                    {
                        // Delete composite entity
                        myCompositeMembersMap.erase(searchComposite);
                        myCompositeStateCacheMap.erase(compositeMoKey);
                    }

                    // Flag current composite entity to be re-evaluated
                    compositeEntityToEvaluateList.push_back(compositeMoKey);

                    // Delete entry MemberOf map
                    myMemberOfMap[compositeMemberMoKey].erase(compositeMoKey);

                    if(myMemberOfMap[compositeMemberMoKey].empty())
                    {
                        myMemberOfMap.erase(compositeMemberMoKey);
                    }

                    break;
                }
            }
        }
    }

    for(auto compositeEntityToEvaluate : compositeEntityToEvaluateList)
    {
        // Re-evaluate composite condition state
        evaluateCompositeState(compositeEntityToEvaluate);
    }
}

void CompositeEntityEngine::deleteComposite(std::shared_ptr<Key> compositeMoKey)
{
    std::deque<std::shared_ptr<Key>> compositeEntityToEvaluateList;

    auto searchComposite = myCompositeMembersMap.find(compositeMoKey);

    if(searchComposite != myCompositeMembersMap.end())
    {
        std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

        for(auto& compositeMember : searchComposite->second)
        {
            // Apply a default state (clear failure state => false) to the member
            compositeMember.second = false;

            auto searchCompositeMember = myMemberOfMap.find(compositeMember.first);

            if(searchCompositeMember != myMemberOfMap.end())
            {
                for(const auto& it : myMemberOfMap[searchCompositeMember->first])
                {
                    // Only delete if the keys match
                    if(*compositeMoKey == *it.first)
                    {
                        // Delete entry MemberOf map
                        myMemberOfMap[searchCompositeMember->first].erase(compositeMoKey);

                        if(myMemberOfMap[searchCompositeMember->first].empty())
                        {
                            myMemberOfMap.erase(searchCompositeMember);
                        }

                        break;
                    }
                }
            }
        }

        // Flag current composite entity to be re-evaluated
        compositeEntityToEvaluateList.push_back(compositeMoKey);

        // Delete composite entity
        myCompositeMembersMap.erase(searchComposite);
        myCompositeStateCacheMap.erase(compositeMoKey);
    }

    for(auto compositeEntityToEvaluate : compositeEntityToEvaluateList)
    {
        // Re-evaluate composite condition state
        evaluateCompositeState(compositeEntityToEvaluate);
    }
}

void CompositeEntityEngine::setCompositeMemberFailureState(std::shared_ptr<Key> compositeMemberMoKey, bool failureState)
{
    std::deque<std::shared_ptr<Key>> compositeEntityToEvaluateList;

    {
        std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

        // Check whether composite entity exists from given member compositeMemberMoKey
        auto searchComposite = myMemberOfMap.find(compositeMemberMoKey);

        if(searchComposite != myMemberOfMap.end())
        {
            for(const auto& it : myMemberOfMap[compositeMemberMoKey])
            {
                std::shared_ptr<Key> compositeEntity = it.first;

                // Affect member failure state
                myCompositeMembersMap[compositeEntity][compositeMemberMoKey] = failureState;

                // Flag current iter composite entity to be re-evaluated
                compositeEntityToEvaluateList.push_back(compositeEntity);
            }
        }
    }

    for(auto compositeEntityToEvaluate : compositeEntityToEvaluateList)
    {
        // Re-evaluate composite condition state
        evaluateCompositeState(compositeEntityToEvaluate);
    }
}

void CompositeEntityEngine::evaluateCompositeState(std::shared_ptr<Key> compositeEntity)
{
    bool doReportState = false;
    CompositeEntityState stateToReport     = CompositeEntityState::IDLE;
    CompositeEntityState prevStateToReport = CompositeEntityState::IDLE;

    {
        std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

        // Check whether composite entity exists
        auto searchComposite = myCompositeMembersMap.find(compositeEntity);

        if(searchComposite != myCompositeMembersMap.end())
        {
            MemberStateMap& compositeMembers = myCompositeMembersMap[compositeEntity];

            // Evaluate composite condition state as follows:
            // => composite entity OK                => all members are OK;
            // => composite entity PARTIALLY FAILURE => at least one member is in failure;
            // => composite entity FAILURE           => all members are in failure;
            bool partiallyFailure = false; // bitwise OR
            bool compositeFailure = true;  // bitwise AND

            for(const auto& member : compositeMembers)
            {
                partiallyFailure |= member.second;
                compositeFailure &= member.second;
            }

            CompositeEntityState newCompositeEntityState = CompositeEntityState::NORMAL;

            if(compositeFailure)
            {
                newCompositeEntityState = CompositeEntityState::COMPOSITE_ENTITY_FAILURE;
            }
            else if(partiallyFailure)
            {
                newCompositeEntityState = CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE;
            }

            // Report composite state only if new/changed state
            // (Note: first time created the state is IDLE => will cause the mismatch!)
            if(newCompositeEntityState != myCompositeStateCacheMap[compositeEntity])
            {
                prevStateToReport = myCompositeStateCacheMap[compositeEntity];
                myCompositeStateCacheMap[compositeEntity] = newCompositeEntityState;

                // Fill-up the the composite state info to be reported
                stateToReport = newCompositeEntityState;
                doReportState = true;
            }
        }
        else
        {
            // No members found => report state IDLE
            stateToReport = CompositeEntityState::IDLE;
            doReportState = true;
        }
    }

    if(doReportState)
    {
        if(myCallbackFunction)
        {
            myCallbackFunction(compositeEntity, stateToReport, prevStateToReport);
        }
    }
}

std::vector<std::shared_ptr<Key>> CompositeEntityEngine::getListOfCompositeEntities() const
{
    std::vector<std::shared_ptr<Key>> ret;

    std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

    for(const auto& compositeEntityIter : myCompositeMembersMap)
    {
        ret.push_back(compositeEntityIter.first);
    }

    return ret;
}

CompositeEntityState CompositeEntityEngine::getCompositeState(std::shared_ptr<Key> compositeMoKey) const
{
    CompositeEntityState ret = CompositeEntityState::IDLE;

    std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

    // Check whether composite entity exists
    auto searchComposite = myCompositeStateCacheMap.find(compositeMoKey);

    if(searchComposite != myCompositeStateCacheMap.end())
    {
        ret = searchComposite->second;
    }

    return ret;
}

std::vector<std::shared_ptr<Key>> CompositeEntityEngine::getListOfMembers(std::shared_ptr<Key> compositeMoKey) const
{
    std::vector<std::shared_ptr<Key>> ret;

    std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

    // Check whether composite entity exists
    auto searchComposite = myCompositeMembersMap.find(compositeMoKey);

    if(searchComposite != myCompositeMembersMap.end())
    {
        for(const auto& memberIter : searchComposite->second)
        {
            ret.push_back(memberIter.first);
        }
    }

    return ret;
}

bool CompositeEntityEngine::getMemberFailureState(std::shared_ptr<Key> compositeMoKey,
                                                  std::shared_ptr<Key> compositeMemberMoKey) const
{
    bool ret = false;

    std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

    // Check whether composite/member entity exists
    auto searchComposite = myCompositeMembersMap.find(compositeMoKey);

    if(searchComposite != myCompositeMembersMap.end())
    {
        auto searchMember = searchComposite->second.find(compositeMemberMoKey);

        if(searchMember != searchComposite->second.end())
        {
            ret = searchMember->second;
        }
    }

    return ret;
}

bool CompositeEntityEngine::isCompositeEntity(std::shared_ptr<Key> moKey) const
{
    return (myCompositeStateCacheMap.find(moKey) != myCompositeStateCacheMap.end());
}

bool CompositeEntityEngine::isMemberOfComposite(std::shared_ptr<Key> compositeMoKey,
                                                std::shared_ptr<Key> compositeMemberMoKey) const
{
    const std::vector<std::shared_ptr<Key>> members = getListOfMembers(compositeMoKey);
    auto search = std::find_if(members.begin(), members.end(), [&](const std::shared_ptr<Key>& ptr)
    {
        return *ptr == *compositeMemberMoKey;
    });
    return (search != members.end());
}

std::string CompositeEntityEngine::toString()
{
    std::stringstream out;

    std::vector<std::shared_ptr<Key>> listOfComposite = getListOfCompositeEntities();

    for(std::shared_ptr<Key> compositeEntityKey : listOfComposite)
    {
        CompositeEntityState compositeEntityState = getCompositeState(compositeEntityKey);

        std::vector<std::shared_ptr<Key>> listOfMembers = getListOfMembers(compositeEntityKey);
        std::string membersStateInfo;

        for(std::shared_ptr<Key> memberKey : listOfMembers)
        {
            bool memberFailureState = getMemberFailureState(compositeEntityKey, memberKey);

            membersStateInfo += memberKey->getShortDescription() + "/" + (memberFailureState ? "Fail" : "Clear") + " ";
        }

        out << "C:" << compositeEntityKey->getShortDescription() << "=" << to_string(compositeEntityState) << ",M:[" <<
            membersStateInfo << "]" << std::endl;
    }

    return out.str();
}
