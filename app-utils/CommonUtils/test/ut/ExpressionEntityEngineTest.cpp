#include <sstream>
#include <algorithm>
#include <iostream>
#include <unordered_map>
#include "gtest/gtest.h"

#include "CommonUtils/ExpressionEntityEngine.h"

class MockExpressionEntityEngine : public ExpressionEntityEngine
{
    public:
        MockExpressionEntityEngine(CompositeEntityCallbackFunctionType callbackFunction)
            : ExpressionEntityEngine(callbackFunction)
        {};

        bool hasExpressionAssociated(std::shared_ptr<Key> moCompositeKey)
        {
            return (myCompositeExpressions.find(moCompositeKey) != myCompositeExpressions.end());
        }
};


class ExpressionEntityEngineTestFixture : public ::testing::Test
{
    protected:
        ExpressionEntityEngineTestFixture()
            : testExpressionEntityEngine_(std::bind(&ExpressionEntityEngineTestFixture::stateEntityCallback,
                                                    this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3))
        {}

        ~ExpressionEntityEngineTestFixture() = default;


        void stateEntityCallback(std::shared_ptr<Key> moKey, const CompositeEntityState& newCompositeState,
                                 const CompositeEntityState& prevCompositeState)
        {
        }

        CompositeEntityState getEntityCompositeState(std::shared_ptr<Key> moKey) const
        {
            return testExpressionEntityEngine_.getCompositeState(moKey);
        }

        void SetUp() override
        {
        }

        MockExpressionEntityEngine testExpressionEntityEngine_;
};

TEST_F(ExpressionEntityEngineTestFixture, creationAndSetExpressionEntity)
{
    std::shared_ptr<Key> oduSuppressionPropagation = std::make_shared<Key>("odu-1", "ODU-INTRUSIVE-CORRELATED");
    std::shared_ptr<Key> ociFault = std::make_shared<Key>("odu-1", "OCI");
    std::shared_ptr<Key> lckFault = std::make_shared<Key>("odu-1", "LCK");
    std::shared_ptr<Key> aisFault = std::make_shared<Key>("odu-1", "AIS");
    std::shared_ptr<Key> timFault = std::make_shared<Key>("odu-1", "TIM");
    std::shared_ptr<Key> timActEnabledConfig = std::make_shared<Key>("odu-1", "TIM-ACT-ENABLED");
    std::shared_ptr<Key> monModeIntrusiveEnabledConfig = std::make_shared<Key>("odu-1", "MON-MODE-INTRUSIVE-ENABLED");

    const std::string expression = "(OCI || LCK || AIS || (TIM && TIM_ACT_ENABLED)) && MON_MODE_INTRUSIVE_ENABLED";

    // Setup the composite relations

    testExpressionEntityEngine_.addCompositeRelation(oduSuppressionPropagation,   // COMPOSITE ENTITY
                                                     expression,                  // EXPRESSION
                                                     ociFault,                    // MEMBER
                                                     "OCI");                      // SYMBOL THAT REPRESENTS THE VARIABLE IN EXPRESSION

    testExpressionEntityEngine_.addCompositeRelation(oduSuppressionPropagation, expression, lckFault, "LCK");
    testExpressionEntityEngine_.addCompositeRelation(oduSuppressionPropagation, expression, aisFault, "AIS");
    testExpressionEntityEngine_.addCompositeRelation(oduSuppressionPropagation, expression, timFault, "TIM");
    testExpressionEntityEngine_.addCompositeRelation(oduSuppressionPropagation, expression, timActEnabledConfig,
                                                     "TIM_ACT_ENABLED");
    testExpressionEntityEngine_.addCompositeRelation(oduSuppressionPropagation, expression, monModeIntrusiveEnabledConfig,
                                                     "MON_MODE_INTRUSIVE_ENABLED");

    // Start testing

    CompositeEntityState currentState = CompositeEntityState::IDLE;

    // Test initial state => IDLE

    currentState = getEntityCompositeState(oduSuppressionPropagation);
    EXPECT_EQ(currentState, CompositeEntityState::IDLE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            oduSuppressionPropagation->getShortDescription();

    // Simulate the enable of intrusive mode

    testExpressionEntityEngine_.setCompositeMemberFailureState(monModeIntrusiveEnabledConfig, true);

    currentState = getEntityCompositeState(oduSuppressionPropagation);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_FALSE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            oduSuppressionPropagation->getShortDescription();

    // Test raise/clear OCI

    testExpressionEntityEngine_.setCompositeMemberFailureState(ociFault, true);

    currentState = getEntityCompositeState(oduSuppressionPropagation);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_TRUE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            oduSuppressionPropagation->getShortDescription();

    testExpressionEntityEngine_.setCompositeMemberFailureState(ociFault, false);

    currentState = getEntityCompositeState(oduSuppressionPropagation);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_FALSE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            oduSuppressionPropagation->getShortDescription();

    // Test with TIM & TIM_ACT_ENABLED

    testExpressionEntityEngine_.setCompositeMemberFailureState(timFault, true);

    currentState = getEntityCompositeState(oduSuppressionPropagation);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_FALSE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            oduSuppressionPropagation->getShortDescription();

    testExpressionEntityEngine_.setCompositeMemberFailureState(timActEnabledConfig, true);

    currentState = getEntityCompositeState(oduSuppressionPropagation);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_TRUE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            oduSuppressionPropagation->getShortDescription();

    testExpressionEntityEngine_.setCompositeMemberFailureState(timFault, false);

    currentState = getEntityCompositeState(oduSuppressionPropagation);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_FALSE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            oduSuppressionPropagation->getShortDescription();

    testExpressionEntityEngine_.setCompositeMemberFailureState(timActEnabledConfig, false);

    currentState = getEntityCompositeState(oduSuppressionPropagation);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_FALSE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            oduSuppressionPropagation->getShortDescription();

    // Test raise LCK and disable intrusive mode

    testExpressionEntityEngine_.setCompositeMemberFailureState(lckFault, true);

    currentState = getEntityCompositeState(oduSuppressionPropagation);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_TRUE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            oduSuppressionPropagation->getShortDescription();

    testExpressionEntityEngine_.setCompositeMemberFailureState(monModeIntrusiveEnabledConfig, false);

    currentState = getEntityCompositeState(oduSuppressionPropagation);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_FALSE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            oduSuppressionPropagation->getShortDescription();
}

TEST_F(ExpressionEntityEngineTestFixture, deleteExpressionMembers)
{
    std::shared_ptr<Key> correlated = std::make_shared<Key>("composite", "ABC");
    std::shared_ptr<Key> memberA    = std::make_shared<Key>("member", "A");
    std::shared_ptr<Key> memberB    = std::make_shared<Key>("member", "B");
    std::shared_ptr<Key> memberC    = std::make_shared<Key>("member", "C");

    const std::string expression = "A || B || C";

    // Register the composite relations
    testExpressionEntityEngine_.addCompositeRelation(correlated, expression, memberA, "A");
    testExpressionEntityEngine_.addCompositeRelation(correlated, expression, memberB, "B");
    testExpressionEntityEngine_.addCompositeRelation(correlated, expression, memberC, "C");

    CompositeEntityState currentState = CompositeEntityState::IDLE;

    currentState = getEntityCompositeState(correlated);
    EXPECT_EQ(currentState, CompositeEntityState::IDLE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            correlated->getShortDescription();

    // Make expression to evaluate true

    testExpressionEntityEngine_.setCompositeMemberFailureState(memberA, true);
    testExpressionEntityEngine_.setCompositeMemberFailureState(memberB, true);
    testExpressionEntityEngine_.setCompositeMemberFailureState(memberC, true);

    currentState = getEntityCompositeState(correlated);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_TRUE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            correlated->getShortDescription();

    // Delete several members and check the result
    // Is expected that when a member is deleted it contributes with false state

    testExpressionEntityEngine_.deleteCompositeMember(memberC);

    currentState = getEntityCompositeState(correlated);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_TRUE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            correlated->getShortDescription();

    testExpressionEntityEngine_.deleteCompositeMember(memberB);

    currentState = getEntityCompositeState(correlated);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_TRUE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            correlated->getShortDescription();

    testExpressionEntityEngine_.deleteCompositeMember(memberA);

    currentState = getEntityCompositeState(correlated);
    EXPECT_EQ(currentState, CompositeEntityState::IDLE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            correlated->getShortDescription();

    EXPECT_FALSE(testExpressionEntityEngine_.hasExpressionAssociated(correlated))
            << "Unexpected registered expression for entity " <<
            correlated->getShortDescription();
}

TEST_F(ExpressionEntityEngineTestFixture, testMultiValueCorrelations)
{
    std::shared_ptr<Key> correlatedContributorA = std::make_shared<Key>("compositeContributorA", "A");
    std::shared_ptr<Key> memberA1    = std::make_shared<Key>("memberA1", "A-1");
    std::shared_ptr<Key> memberA2    = std::make_shared<Key>("memberA2", "A-2");

    std::shared_ptr<Key> correlatedContributorB = std::make_shared<Key>("compositeContributorB", "B");
    std::shared_ptr<Key> memberB1    = std::make_shared<Key>("memberB1", "B-1");
    std::shared_ptr<Key> memberB2    = std::make_shared<Key>("memberB2", "B-2");

    std::shared_ptr<Key> correlatedAggregator = std::make_shared<Key>("compositeAggregator", "");

    // Register the relations

    // - Contributors
    testExpressionEntityEngine_.addCompositeRelation(correlatedContributorA, {"A1 || A2"}, memberA1, "A1");
    testExpressionEntityEngine_.addCompositeRelation(correlatedContributorA, {"A1 || A2"}, memberA2, "A2");

    testExpressionEntityEngine_.addCompositeRelation(correlatedContributorB, {"B1 || B2"}, memberB1, "B1");
    testExpressionEntityEngine_.addCompositeRelation(correlatedContributorB, {"B1 || B2"}, memberB2, "B2");

    // - Aggregator
    testExpressionEntityEngine_.addCompositeRelation(correlatedAggregator, {"#AND(Contributors[])"}, correlatedContributorA,
                                                     "Contributors[]");
    testExpressionEntityEngine_.addCompositeRelation(correlatedAggregator, {"#AND(Contributors[])"}, correlatedContributorB,
                                                     "Contributors[]");

    // Test initial state

    CompositeEntityState currentState = CompositeEntityState::IDLE;

    currentState = getEntityCompositeState(correlatedContributorA);
    EXPECT_EQ(currentState, CompositeEntityState::IDLE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            correlatedContributorA->getShortDescription();

    currentState = getEntityCompositeState(correlatedAggregator);
    EXPECT_EQ(currentState, CompositeEntityState::IDLE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            correlatedAggregator->getShortDescription();

    // Raise Contributor A

    testExpressionEntityEngine_.setCompositeMemberFailureState(memberA1, true);

    currentState = getEntityCompositeState(correlatedContributorA);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_TRUE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            correlatedContributorA->getShortDescription();

    // Feed the engine with the contributorA state (evaluated true above)
    testExpressionEntityEngine_.setCompositeMemberFailureState(correlatedContributorA, true);

    currentState = getEntityCompositeState(correlatedAggregator);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_FALSE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            correlatedAggregator->getShortDescription();

    // Raise Contributor B

    testExpressionEntityEngine_.setCompositeMemberFailureState(memberB1, true);

    currentState = getEntityCompositeState(correlatedContributorB);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_TRUE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            correlatedContributorB->getShortDescription();

    // Feed the engine with the contributorB state (evaluated true above)
    testExpressionEntityEngine_.setCompositeMemberFailureState(correlatedContributorB, true);

    currentState = getEntityCompositeState(correlatedAggregator);
    EXPECT_EQ(currentState, CompositeEntityState::CUSTOM_EXPRESSION_EVALUATED_TRUE)
            << "Unexpected composite state " << to_string(currentState) << " for entity " <<
            correlatedAggregator->getShortDescription();
}
