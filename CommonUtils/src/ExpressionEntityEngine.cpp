#include "CommonUtils/ExpressionEntityEngine.h"

ExpressionEntityEngine::ExpressionEntityEngine(CompositeEntityCallbackFunctionType callbackFunction)
    : CompositeEntityEngine(callbackFunction)
{
}

ExpressionEntityEngine::~ExpressionEntityEngine()
{
}

void ExpressionEntityEngine::addCompositeRelation(std::shared_ptr<Key> compositeMoKey,
                                                  const std::string& evaluationStateExpression,
                                                  std::shared_ptr<Key> compositeMemberMoKey, const std::string& symbolInExpression)
{
    std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

    // Call base function to maintain the composite/members storage and callback functionality from the base
    CompositeEntityEngine::addCompositeRelation(compositeMoKey, compositeMemberMoKey);

    // Create an expression and assign it to the composite entity (if not already defined)
    auto searchCompositeExpression = myCompositeExpressions.find(compositeMoKey);

    if(searchCompositeExpression == myCompositeExpressions.end())
    {
        try
        {
            Expression expression(evaluationStateExpression);
            myCompositeExpressions.insert({compositeMoKey, std::move(expression)});
        }
        catch(const std::exception& ex)
        {
            throw; // Rethrowing
        }
    }

    // Store the member symbol, in association with composite member
    myMemberSymbolsMapping[compositeMemberMoKey][compositeMoKey] = symbolInExpression;
}

void ExpressionEntityEngine::deleteCompositeMember(std::shared_ptr<Key> compositeMemberMoKey)
{
    // 1st) Before effectively deleting, declare member with default state = false
    // This efectively will make the associated expression to be evaluated and (new) result state will be propagated (if differs)
    setCompositeMemberFailureState(compositeMemberMoKey, false);

    // 2nd) Call base function to delete internal composite/members storage
    CompositeEntityEngine::deleteCompositeMember(compositeMemberMoKey);

    {
        std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

        // 3rd) Update local storage, including removing references to the member being deleted

        auto searchMember = myMemberSymbolsMapping.find(compositeMemberMoKey);

        if(searchMember != myMemberSymbolsMapping.end())
        {
            // Delete entry MemberOf map
            myMemberOfMap.erase(compositeMemberMoKey);
        }

        // 4th) If this member deletion makes it so that the composite is empty of members, then the composite will be deleted
        //      In such a scenario, it is necessary to update the expression storage as well
        std::vector<std::shared_ptr<Key>> clearLocalExpressionCacheEntities;

        for(const auto& compositeIter : myCompositeExpressions)
        {
            if(myCompositeMembersMap.end() == myCompositeMembersMap.find(compositeIter.first))
            {
                clearLocalExpressionCacheEntities.push_back(compositeIter.first);
            }
        }

        // Update local expression cache by effectively deleting composite entities
        for(const auto& compositeEntity : clearLocalExpressionCacheEntities)
        {
            ExpressionEntityEngine::deleteComposite(compositeEntity);
        }
    }
}

void ExpressionEntityEngine::deleteComposite(std::shared_ptr<Key> compositeMoKey)
{
    // 1st) Call base function to delete internal composite/members storage
    // This efectively will make the associated expression to be evaluated and (new) result state will be propagated (if different)
    CompositeEntityEngine::deleteComposite(compositeMoKey);

    // 2nd) Update local storage
    {
        std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

        auto searchCompositeExpression = myCompositeExpressions.find(compositeMoKey);

        if(searchCompositeExpression != myCompositeExpressions.end())
        {
            myCompositeExpressions.erase(compositeMoKey);
        }
    }
}

void ExpressionEntityEngine::evaluateCompositeState(std::shared_ptr<Key> compositeEntity)
{
    bool doReportState = false;
    CompositeEntityState stateToReport     = CompositeEntityState::IDLE;
    CompositeEntityState prevStateToReport = CompositeEntityState::IDLE;

    {
        std::lock_guard<std::recursive_mutex> lock(myCompositeMutex);

        // Check whether composite entity exists
        auto searchComposite = myCompositeMembersMap.find(compositeEntity);
        auto searchCompositeExpression = myCompositeExpressions.find(compositeEntity);

        if(searchComposite != myCompositeMembersMap.end() &&
           searchCompositeExpression != myCompositeExpressions.end())
        {
            // Get the related members
            MemberStateMap& compositeMembers = searchComposite->second;

            // Get the related expression
            Expression& compositeExpression = searchCompositeExpression->second;

            // Set in expression the symbol and corresponding state value that represents the member
            for(const auto& member : compositeMembers)
            {
                const std::string& memberSymbol = myMemberSymbolsMapping[member.first][compositeEntity];

                // In case is a multi-value variable (includes '[]' in the name) insert a value in the operand token
                if(std::string::npos != memberSymbol.find("[]"))
                {
                    compositeExpression.setOperandVariableMultiValue(memberSymbol, member.first->getEntity(),
                                                                     static_cast<double>(member.second));
                }
                else
                {
                    compositeExpression.setOperandVariable(memberSymbol, static_cast<double>(member.second));
                }
            }

            CompositeEntityState newCompositeEntityState =
                compositeExpression.evaluateBool() ? CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_TRUE
                : CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_FALSE;

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

    if(doReportState && myCallbackFunction)
    {
        myCallbackFunction(compositeEntity, stateToReport, prevStateToReport);
    }
}

std::string ExpressionEntityEngine::getAssociatedExpression(std::shared_ptr<Key> compositeEntity) const
{
    std::string ret;

    auto searchCompositeExpression = myCompositeExpressions.find(compositeEntity);

    if(searchCompositeExpression != myCompositeExpressions.end())
    {
        return searchCompositeExpression->second.getInfixExpression();
    }

    return ret;
}

std::string ExpressionEntityEngine::toString()
{
    std::string ret;
    ret = CompositeEntityEngine::toString();

    for(const auto& exprIter : myCompositeExpressions)
    {
        ret.append("\n");
        ret.append(exprIter.first->getShortDescription());
        ret.append(" => Expression: ");
        ret.append(exprIter.second.to_string());
    }

    return ret;
}
