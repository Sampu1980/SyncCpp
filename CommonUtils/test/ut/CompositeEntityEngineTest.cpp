#include <sstream>
#include <algorithm>
#include <unordered_map>
#include "gtest/gtest.h"

#include "CommonUtils/CompositeEntityEngine.h"

class MockCompositeEntity : public CompositeEntityEngine
{
    public:
        MockCompositeEntity(CompositeEntityCallbackFunctionType callback)
            : CompositeEntityEngine(callback)
        {};
};

class CompositeEntityEngineTestFixture : public ::testing::Test
{
    protected:
        CompositeEntityEngineTestFixture()
            : testCompositeEntityEngine_(std::bind(&CompositeEntityEngineTestFixture::compositeStateEntityCallback,
                                                   this, std::placeholders::_1, std::placeholders::_2))
        {}

        ~CompositeEntityEngineTestFixture() = default;


        void compositeStateEntityCallback(std::shared_ptr<Key> moKey, const CompositeEntityState& compositeState)
        {
            // NOTE: the callback implements a reset of the affected composite state to the engine to stimulate
            // other composite entities which have the given key as member
            // Different behaviors can be implemented/considered, i.e. partial failure might not be considered a failure
            // Behavior here implemented is that any failure is signaled as fail state to the composite entities it is member
            bool fail = (CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE == compositeState ||
                         CompositeEntityState::COMPOSITE_ENTITY_FAILURE == compositeState);

            testCompositeEntityEngine_.setCompositeMemberFailureState(moKey, fail);
        }

        CompositeEntityState getEntityCompositeState(std::shared_ptr<Key> moKey) const
        {
            return testCompositeEntityEngine_.getCompositeState(moKey);
        }

        void SetUp() override
        {
        }

        MockCompositeEntity testCompositeEntityEngine_;
};

// Test dual carrier scenario:
// - creation of a composite entity and its members.
// - set members state and evaluate composite state output report
TEST_F(CompositeEntityEngineTestFixture, creationAndSetCompositeEntity)
{
    std::shared_ptr<Key> superChannelKey = std::make_shared<Key>("sch-1", "SCHPTP");
    std::shared_ptr<Key> carrier1Key = std::make_shared<Key>("carrier-1", "CarrierCtp");
    std::shared_ptr<Key> carrier2Key = std::make_shared<Key>("carrier-2", "CarrierCtp");

    // Register the composite relations
    testCompositeEntityEngine_.addCompositeRelation(superChannelKey, carrier1Key);
    testCompositeEntityEngine_.addCompositeRelation(superChannelKey, carrier2Key);

    // Validate initial state of the composite entity
    EXPECT_EQ(testCompositeEntityEngine_.getCompositeState(superChannelKey), CompositeEntityState::IDLE)
            << "Initial composite state NOT as expected!";

    // Test NORMAL state
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier1Key, false); // No failure
    EXPECT_EQ(getEntityCompositeState(superChannelKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << superChannelKey->getShortDescription();

    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier2Key, false); // No failure
    EXPECT_EQ(getEntityCompositeState(superChannelKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << superChannelKey->getShortDescription();

    // Test NORMAL -> COMPOSITE_ENTITY_PARTIAL_FAILURE state
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier1Key, true); // Failure
    EXPECT_EQ(getEntityCompositeState(superChannelKey), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << superChannelKey->getShortDescription();

    // Test COMPOSITE_ENTITY_PARTIAL_FAILURE -> COMPOSITE_ENTITY_FAILURE state
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier2Key, true); // Failure
    EXPECT_EQ(getEntityCompositeState(superChannelKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << superChannelKey->getShortDescription();

    // Test COMPOSITE_ENTITY_FAILURE -> COMPOSITE_ENTITY_PARTIAL_FAILURE state
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier2Key, false); // No failure
    EXPECT_EQ(getEntityCompositeState(superChannelKey), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << superChannelKey->getShortDescription();

    // Test COMPOSITE_ENTITY_PARTIAL_FAILURE -> NORMAL
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier1Key, false); // No failure
    EXPECT_EQ(getEntityCompositeState(superChannelKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << superChannelKey->getShortDescription();
}

// Test dual carrier scenario:
// - delete members and check full composite entity recover (to IDLE)
TEST_F(CompositeEntityEngineTestFixture, deleteCompositeMembers)
{
    std::shared_ptr<Key> superChannelKey = std::make_shared<Key>("sch-1", "SCHPTP");
    std::shared_ptr<Key> carrier1Key = std::make_shared<Key>("carrier-1", "CarrierCtp");
    std::shared_ptr<Key> carrier2Key = std::make_shared<Key>("carrier-2", "CarrierCtp");

    // Register the composite relations
    testCompositeEntityEngine_.addCompositeRelation(superChannelKey, carrier1Key);
    testCompositeEntityEngine_.addCompositeRelation(superChannelKey, carrier2Key);

    // Test COMPOSITE_ENTITY_FAILURE
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier1Key, true); // Failure
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier2Key, true); // Failure

    EXPECT_EQ(getEntityCompositeState(superChannelKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << superChannelKey->getShortDescription();

    // Test still COMPOSITE_ENTITY_FAILURE
    // (Delete members while composite entity still in failure)
    testCompositeEntityEngine_.deleteCompositeMember(carrier2Key);
    EXPECT_EQ(getEntityCompositeState(superChannelKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << superChannelKey->getShortDescription();

    // Test COMPOSITE_ENTITY_FAILURE -> IDLE
    // (Delete last member while composite entity still in failure)
    testCompositeEntityEngine_.deleteCompositeMember(carrier1Key);
    EXPECT_EQ(getEntityCompositeState(superChannelKey), CompositeEntityState::IDLE)
            << "Unexpected composite state for entity " << superChannelKey->getShortDescription();
}

// Test scenario where an entity is member on more than one composite entity
// Validate the delete individually and simultaneously in both groups
// (currently can only occur temporarily when the configuration is being updated)
TEST_F(CompositeEntityEngineTestFixture, testMemberOfMultipleCompositeEntities)
{
    std::shared_ptr<Key> superChannelKey = std::make_shared<Key>("sch-1", "SCHPTP", false);
    std::shared_ptr<Key> carrier1Key = std::make_shared<Key>("carrier-1", "CarrierCtp", false);
    std::shared_ptr<Key> carrier2Key = std::make_shared<Key>("carrier-2", "CarrierCtp", false);
    std::shared_ptr<Key> loOdu1Key = std::make_shared<Key>("odu4i-1", "LO-ODU", false);
    std::shared_ptr<Key> loOdu2Key = std::make_shared<Key>("odu4i-2", "LO-ODU", false);
    std::shared_ptr<Key> loOdu3Key = std::make_shared<Key>("odu4i-3", "LO-ODU", false);

    // Register the composite relations
    testCompositeEntityEngine_.addCompositeRelation(superChannelKey, carrier1Key);
    testCompositeEntityEngine_.addCompositeRelation(superChannelKey, carrier2Key);

    testCompositeEntityEngine_.addCompositeRelation(carrier1Key, loOdu1Key);
    testCompositeEntityEngine_.addCompositeRelation(carrier2Key, loOdu2Key);
    // - lo-odu3 is member of both carriers
    testCompositeEntityEngine_.addCompositeRelation(carrier1Key, loOdu3Key);
    testCompositeEntityEngine_.addCompositeRelation(carrier2Key, loOdu3Key);

    // Test COMPOSITE_ENTITY_PARTIAL_FAILURE
    testCompositeEntityEngine_.setCompositeMemberFailureState(loOdu3Key, true); // Failure
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();

    // Test COMPOSITE_ENTITY_FAILURE on carrier1
    testCompositeEntityEngine_.setCompositeMemberFailureState(loOdu1Key, true); // Failure
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();

    // Test COMPOSITE_ENTITY_FAILURE on carrier2
    testCompositeEntityEngine_.setCompositeMemberFailureState(loOdu2Key, true); // Failure
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();

    // Test COMPOSITE_ENTITY_PARTIAL_FAILURE on both carriers (by restoring state of lo-odu3)
    testCompositeEntityEngine_.setCompositeMemberFailureState(loOdu3Key, false); // Normal
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();

    // Test COMPOSITE_ENTITY_FAILURE on both carriers (by deleting lo-odu3)
    testCompositeEntityEngine_.deleteCompositeMember(loOdu3Key);
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();

    // Add back lo-odu3 to both carriers
    testCompositeEntityEngine_.addCompositeRelation(carrier1Key, loOdu3Key);
    testCompositeEntityEngine_.addCompositeRelation(carrier2Key, loOdu3Key);

    // Test COMPOSITE_ENTITY_PARTIAL_FAILURE on both carriers (no failure in lo-odu3)
    testCompositeEntityEngine_.setCompositeMemberFailureState(loOdu3Key, false); // Normal
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();

    // Test COMPOSITE_ENTITY_FAILURE in carrier 1 (by deleting lo-odu3)
    testCompositeEntityEngine_.deleteCompositeMember(carrier1Key, loOdu3Key);
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();

    // Test COMPOSITE_ENTITY_FAILURE in carrier 2 (by deleting lo-odu3)
    testCompositeEntityEngine_.deleteCompositeMember(carrier2Key, loOdu3Key);
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();

    // Test COMPOSITE_ENTITY_FAILURE -> IDLE on carrier 1
    // by deleting last member while composite entity still in failure
    testCompositeEntityEngine_.deleteCompositeMember(loOdu1Key);
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::IDLE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();

    // Test COMPOSITE_ENTITY_FAILURE -> IDLE on carrier 2
    // by deleting last member while composite entity still in failure
    testCompositeEntityEngine_.deleteCompositeMember(loOdu2Key);
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::IDLE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();
}

// Test dual carrier scenario:
// - composite entity is set by other composite entities
// - creation of a composite entity and its members
// - set members state and evaluate composite state output report
// - delete members and evaluate composite state output report
TEST_F(CompositeEntityEngineTestFixture, creationAndSetMultipleCompositeEntities)
{
    std::shared_ptr<Key> moKey = std::make_shared<Key>("sch-1", "SCHPTP");
    std::shared_ptr<Key> moFaultKey = std::make_shared<Key>("sch-1", "OLOS");
    std::shared_ptr<Key> carrier1Key = std::make_shared<Key>("carrier-1", "CarrierCTP");
    std::shared_ptr<Key> carrier2Key = std::make_shared<Key>("carrier-2", "CarrierCTP");
    std::shared_ptr<Key> carrier1LofKey = std::make_shared<Key>("carrier-1", "LOF");
    std::shared_ptr<Key> carrier1SfKey = std::make_shared<Key>("carrier-1", "SF");
    std::shared_ptr<Key> carrier2LofKey = std::make_shared<Key>("carrier-2", "LOF");
    std::shared_ptr<Key> carrier2SfKey = std::make_shared<Key>("carrier-2", "SF");

    // Register the composite relations
    testCompositeEntityEngine_.addCompositeRelation(carrier1Key, carrier1LofKey);
    testCompositeEntityEngine_.addCompositeRelation(carrier1Key, carrier1SfKey);

    testCompositeEntityEngine_.addCompositeRelation(carrier2Key, carrier2LofKey);
    testCompositeEntityEngine_.addCompositeRelation(carrier2Key, carrier2SfKey);

    testCompositeEntityEngine_.addCompositeRelation(moFaultKey, carrier2Key);
    testCompositeEntityEngine_.addCompositeRelation(moFaultKey, carrier1Key);

    testCompositeEntityEngine_.addCompositeRelation(moKey, moFaultKey);

    // Validate initial state of the composite entities
    EXPECT_EQ(testCompositeEntityEngine_.getCompositeState(moKey), CompositeEntityState::IDLE)
            << "Initial moKey composite state NOT as expected!";
    EXPECT_EQ(testCompositeEntityEngine_.getCompositeState(moFaultKey), CompositeEntityState::IDLE)
            << "Initial moFaultKey composite state NOT as expected!";
    EXPECT_EQ(testCompositeEntityEngine_.getCompositeState(carrier1Key), CompositeEntityState::IDLE)
            << "Initial carrier1Key composite state NOT as expected!";
    EXPECT_EQ(testCompositeEntityEngine_.getCompositeState(carrier2Key), CompositeEntityState::IDLE)
            << "Initial carrier2Key composite state NOT as expected!";

    // Test clear of carrier1LofKey and verify:
    // - IDLE -> NORMAL state for carrier1Key
    // - IDLE -> NORMAL state for moFaultKey
    // - IDLE -> NORMAL state for moKey
    // - no state change for composite carrier2Key
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier1LofKey, false);
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << moKey->getShortDescription();
    EXPECT_EQ(testCompositeEntityEngine_.getCompositeState(carrier2Key), CompositeEntityState::IDLE)
            << "Initial carrier2Key composite state NOT as expected!";

    // Test clear of carrier2SfKey and verify:
    // - IDLE -> NORMAL state for carrier2Key
    // - no state change for composite carrier1Key, moFaultKey and moKey
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier2SfKey, false);
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << moKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();

    // Test raise a entity not used in composite entities and verify:
    // - no change in composite entities carrier1Key, carrier2Key, moFaultkey and moKey
    std::shared_ptr<Key> ramdomFault = std::make_shared<Key>("undefined", "undefined");
    testCompositeEntityEngine_.setCompositeMemberFailureState(ramdomFault, true);
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << moKey->getShortDescription();

    // Test raise of carrier2SfKey and verify:
    // - NORMAL -> COMPOSITE_ENTITY_PARTIAL_FAILURE state for carrier2Key
    // - NORMAL -> COMPOSITE_ENTITY_PARTIAL_FAILURE state for moFaultKey
    // - NORMAL -> COMPOSITE_ENTITY_FAILURE state for moKey
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier2SfKey, true);
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moKey->getShortDescription();

    // Test raise of carrier2LofKey and verify:
    // - COMPOSITE_ENTITY_PARTIAL_FAILURE -> COMPOSITE_ENTITY_FAILURE state for carrier2Key
    // - no state change on composite moFaultKey and moKey
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier2LofKey, true);
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();

    // Test raise of carrier1LofKey and verify:
    // - NORMAL -> COMPOSITE_ENTITY_PARTIAL_FAILURE state for carrier1Key
    // - COMPOSITE_ENTITY_PARTIAL_FAILURE -> COMPOSITE_ENTITY_FAILURE state for moFaultKey
    // - no state change on composite moKey
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier1LofKey, true);
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moKey->getShortDescription();

    // Test raise of carrier1SfKey and verify:
    // - COMPOSITE_ENTITY_PARTIAL_FAILURE -> COMPOSITE_ENTITY_FAILURE state for carrier1Key
    // - no state change on composite moFaultKey and moKey
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier1SfKey, true);
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moKey->getShortDescription();

    // Test clear of carrier2SfKey and verify:
    // - COMPOSITE_ENTITY_FAILURE -> COMPOSITE_ENTITY_PARTIAL_FAILURE state for carrier2Key
    // - no state change on composite moFaultKey and moKey
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier2SfKey, false);
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moKey->getShortDescription();

    // Test deletion of carrier2LofKey composite member and verify:
    // - COMPOSITE_ENTITY_PARTIAL_FAILURE -> NORMAL state for composite carrier2Key
    // - COMPOSITE_ENTITY_FAILURE -> COMPOSITE_ENTITY_PARTIAL_FAILURE state for composite moFaultKey
    // - no state change in composite moKey
    testCompositeEntityEngine_.deleteCompositeMember(carrier2LofKey);
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moKey->getShortDescription();

    // Test deletion of carrier2SfKey composite member and verify:
    // - NORMAL -> IDLE state for composite carrier2Key
    // - no state change in composite moFaultKey and moKey
    testCompositeEntityEngine_.deleteCompositeMember(carrier2SfKey);
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::IDLE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moKey->getShortDescription();

    // Test deletion of carrier1SfKey composite member and verify:
    // - no state change in composite carrier1Key, moFaultKey and moKey
    testCompositeEntityEngine_.deleteCompositeMember(carrier1SfKey);
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moKey->getShortDescription();

    // Test deletion of carrier2Key composite member and verify:
    // - COMPOSITE_ENTITY_PARTIAL_FAILURE -> COMPOSITE_ENTITY_FAILURE state for composite moFaultKey
    // - no state change for composite mokey
    testCompositeEntityEngine_.deleteCompositeMember(carrier2Key);
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::COMPOSITE_ENTITY_FAILURE)
            << "Unexpected composite state for entity " << moKey->getShortDescription();

    // Test clear of carrier1LofKey and verify:
    // - COMPOSITE_ENTITY_FAILURE -> NORMAL state for composite carrier1Key
    // - COMPOSITE_ENTITY_FAILURE -> NORMAL state for composite moFaultKey
    // - COMPOSITE_ENTITY_FAILURE -> NORMAL state for composite moKey
    testCompositeEntityEngine_.setCompositeMemberFailureState(carrier1LofKey, false);
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << moKey->getShortDescription();

    // Test deletion of carrier1Key composite member and verify:
    // - NORMAL -> IDLE state for composite moFaultKey
    // - no state change for composite moKey
    testCompositeEntityEngine_.deleteCompositeMember(carrier1Key);
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::NORMAL)
            << "Unexpected composite state for entity " << moKey->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(moFaultKey), CompositeEntityState::IDLE)
            << "Unexpected composite state for entity " << moFaultKey->getShortDescription();

    // Test deletion of moFaultKey of composite member and verify:
    // - NORMAL -> IDLE state for composite moKey
    testCompositeEntityEngine_.deleteCompositeMember(moFaultKey);
    EXPECT_EQ(getEntityCompositeState(moKey), CompositeEntityState::IDLE)
            << "Unexpected composite state for entity " << moKey->getShortDescription();
}

// Test deletion of all the members of a composite
TEST_F(CompositeEntityEngineTestFixture, testDeleteComposite)
{
    std::shared_ptr<Key> superChannelKey = std::make_shared<Key>("sch-1", "SCHPTP", false);
    std::shared_ptr<Key> carrier1Key = std::make_shared<Key>("carrier-1", "CarrierCtp", false);
    std::shared_ptr<Key> carrier2Key = std::make_shared<Key>("carrier-2", "CarrierCtp", false);
    std::shared_ptr<Key> loOdu1Key = std::make_shared<Key>("odu4i-1", "LO-ODU", false);
    std::shared_ptr<Key> loOdu2Key = std::make_shared<Key>("odu4i-2", "LO-ODU", false);
    std::shared_ptr<Key> loOdu3Key = std::make_shared<Key>("odu4i-3", "LO-ODU", false);

    // Register the composite relations
    testCompositeEntityEngine_.addCompositeRelation(superChannelKey, carrier1Key);
    testCompositeEntityEngine_.addCompositeRelation(superChannelKey, carrier2Key);

    testCompositeEntityEngine_.addCompositeRelation(carrier1Key, loOdu1Key);
    testCompositeEntityEngine_.addCompositeRelation(carrier2Key, loOdu2Key);
    // - lo-odu3 is member of both carriers
    testCompositeEntityEngine_.addCompositeRelation(carrier1Key, loOdu3Key);
    testCompositeEntityEngine_.addCompositeRelation(carrier2Key, loOdu3Key);

    // Test COMPOSITE_ENTITY_PARTIAL_FAILURE
    testCompositeEntityEngine_.setCompositeMemberFailureState(loOdu3Key, true); // Failure
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();

    // Test COMPOSITE_ENTITY_FAILURE on remaining carrier (by deleting lo-odu3)
    testCompositeEntityEngine_.deleteComposite(carrier2Key);
    EXPECT_EQ(getEntityCompositeState(carrier1Key), CompositeEntityState::COMPOSITE_ENTITY_PARTIAL_FAILURE)
            << "Unexpected composite state for entity " << carrier1Key->getShortDescription();

    // Test COMPOSITE_ENTITY_FAILURE -> IDLE on carrier 2
    EXPECT_EQ(getEntityCompositeState(carrier2Key), CompositeEntityState::IDLE)
            << "Unexpected composite state for entity " << carrier2Key->getShortDescription();
}
