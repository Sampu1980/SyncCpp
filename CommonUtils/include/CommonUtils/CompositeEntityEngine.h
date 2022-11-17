#ifndef COMPOSITEENTITYENGINE_H
#define COMPOSITEENTITYENGINE_H

#include <mutex>
#include <memory>
#include <unordered_map>
#include "CommonUtils/Key.h"

enum class CompositeEntityState
{
    IDLE = 0,
    // COMPOSITE BASE FUNCTIONALITY
    NORMAL,
    COMPOSITE_ENTITY_PARTIAL_FAILURE,
    COMPOSITE_ENTITY_FAILURE,
    // EXPRESSION (specialization)
    CUSTOM_EXPRESSION_EVALUATED_FALSE,
    CUSTOM_EXPRESSION_EVALUATED_TRUE,
};
std::string to_string(CompositeEntityState val);

/**
 * @brief Callback function type to be invoked whenever the state of a composite entity change state.
 * @param moKey the key that uniquely identifies the composite entity
 * @param newCompositeState the new state for the composite entity
 * @param prevCompositeState the previous state of the composite entity
 * @note in case both new and previous state reports IDLE, means that all the members of composite state were deleted
 */
typedef std::function<void (std::shared_ptr<Key> moKey, const CompositeEntityState& newCompositeState, const CompositeEntityState& prevCompositeState)>
CompositeEntityCallbackFunctionType;

/**
 * @class CompositeEntityEngine
 * @brief This class is responsible to manage the state of a composite entity.
 *
 * It allows to register member of a composite entity by calling addCompositeRelation method:
 * -> param a composite entity;
 * -> param a member a of the composite entity;
 * This method shall be called as many times as the number of existing members.
 *
 * From here, whenever the failure state of a composite member change the
 * engine shall be updated by calling setCompositeMemberFailureState.
 * The engine will calculate the new state and will trigger the registered callback.
 *
 * A composite entity have the following possible states:
 * -> IDLE : indicates that state is not determined yet (initial state);
 * -> NORMAL : All member(s) of a composite entity are NOT in failing state;
 * -> COMPOSITE_ENTITY_PARTIAL_FAILURE : Part of the members of a composite entity are in failing state;
 * -> COMPOSITE_ENTITY_FAILURE : All member(s) of a composite entity are in failing state;
 *
 * @see CompositeEntityState
 */
class CompositeEntityEngine
{
    public:
        CompositeEntityEngine() = delete;

        /**
         * @brief Constructor
         * @param supportingEntityCallbackFunction callback function to be executed whenever the state
                                                   of a composite entity changes.
         */
        CompositeEntityEngine(CompositeEntityCallbackFunctionType compositeEntityCallbackFunction);

        /**
         * @brief Default destructor
         */
        virtual ~CompositeEntityEngine() = default;

        /**
         * @brief Register the given compositeMemberMoKey as member of composite entity compositeMoKey.
         * @param compositeMoKey the composite entity key
         * @param compositeMemberMoKey the composite member key
         */
        virtual void addCompositeRelation(std::shared_ptr<Key> compositeMoKey, std::shared_ptr<Key> compositeMemberMoKey);

        /**
         * @brief Unregister the given compositeMemberMoKey from the member list of all associated composite entities.
         * @param compositeMemberMoKey the composite member key
         */
        virtual void deleteCompositeMember(std::shared_ptr<Key> compositeMemberMoKey);

        /**
         * @brief Unregister the given compositeMemberMoKey from the member list of the given composite entity.
         * @param compositeMoKey the composite MO key
         * @param compositeMemberMoKey the composite member key
         */
        virtual void deleteCompositeMember(std::shared_ptr<Key> compositeMoKey, std::shared_ptr<Key> compositeMemberMoKey);

        /**
         * @brief Unregister the complete composite entity and remove all of its members.
         * @param compositeMoKey the composite MO key
         */
        virtual void deleteComposite(std::shared_ptr<Key> compositeMoKey);

        /**
         * @brief Update the failure state of the given composite member compositeMemberMoKey
         *        This will impact all composite entities that have compositeMemberMoKey as member.
         *        The registered callback CompositeEntityCallbackFunctionType will be executed
         *        for each affected composite entities.
         * @param compositeMemberMoKey the composite member key
         * @param failureState boolean representing the failure state
         */
        void setCompositeMemberFailureState(std::shared_ptr<Key> compositeMemberMoKey, bool failureState);

        /**
         * @brief Gather the list of registered composite entities.
         * @return vector listing the registered composite entities.
         */
        std::vector<std::shared_ptr<Key>> getListOfCompositeEntities() const;

        /**
         * @brief Gather the state of given composite entity compositeMoKey
         * @param compositeMoKey the composite entity key
         * @return CompositeEntityState the state of composite entity
         * @see CompositeEntityState
         */
        CompositeEntityState getCompositeState(std::shared_ptr<Key> compositeMoKey) const;

        /**
         * @brief Gather the list of members of the given composite entity compositeMoKey.
         * @param compositeMoKey the composite entity key
         * @return vector listing the members
         */
        std::vector<std::shared_ptr<Key>> getListOfMembers(std::shared_ptr<Key> compositeMoKey) const;

        /**
         * @brief Gather the failure state of given member compositeMemberMoKey of given composite entity compositeMoKey
         * @param compositeMoKey the composite entity key
         * @param compositeMemberMoKey the composite member key
         * @return true if member is in failure; false otherwise
         */
        bool getMemberFailureState(std::shared_ptr<Key> compositeMoKey, std::shared_ptr<Key> compositeMemberMoKey) const;

        /**
         * @brief Evaluate whether given MO is a composite entity.
         * @param moKey the entity key to check if is composite
         * @return true if is composite; false otherwise
         */
        bool isCompositeEntity(std::shared_ptr<Key> moKey) const;

        /**
         * @brief Evaluate whether given MO is member of given composite.
         * @param compositeMoKey the composite entity key
         * @param compositeMemberMoKey the composite member key
         * @return true if is member of composite; false otherwise
         */
        bool isMemberOfComposite(std::shared_ptr<Key> compositeMoKey, std::shared_ptr<Key> compositeMemberMoKey) const;

        /**
         * @brief Compose a string with next info:
         * - the registered composite entities and their state
         * - the registered composite member, which composite members are related and their state
         * @return string with composite engine info
         */
        virtual std::string toString();

    protected:
        /**
         * @brief Internal method to evaluates the state of the given composite entity compositeEntity.
         *        Iterate through all member and determine the composite state as follows:
         *        -> NORMAL : All member(s) of a composite entity are NOT in failing state;
         *        -> COMPOSITE_ENTITY_PARTIAL_FAILURE : Part of the members of a composite entity are in failing state;
         *        -> COMPOSITE_ENTITY_FAILURE : All member(s) of a composite entity are in failing state;
         */
        virtual void evaluateCompositeState(std::shared_ptr<Key> compositeEntity);

        typedef std::unordered_map<std::shared_ptr<Key>, bool, PolymorphicKeyHasher> MemberStateMap;
        /// Map defining a composite entity (key) and its members (list)
        std::unordered_map<std::shared_ptr<Key>, MemberStateMap, PolymorphicKeyHasher> myCompositeMembersMap;
        typedef std::unordered_map<std::shared_ptr<Key>, bool, PolymorphicKeyHasher> AssociatedCompositeMap;
        /// Implements the following mapping: composite member (key) => associated composite entities
        std::unordered_map<std::shared_ptr<Key>, AssociatedCompositeMap, PolymorphicKeyHasher> myMemberOfMap;
        /// Cache that stores the state of a composite entity
        std::unordered_map<std::shared_ptr<Key>, CompositeEntityState, PolymorphicKeyHasher> myCompositeStateCacheMap;
        CompositeEntityCallbackFunctionType myCallbackFunction; ///< Instance of the callback
        /**
         * @brief Mutex to protect operation on the container members
         * This is defined to be recursive in order to be used by specialization classes (e.g. ExpressionEntityEngine)
         * where the chain of calls may result having this mutex being locked twice.
         * e.g.
         *   ExpressionEntityEngine implements a specialized version of addCompositeRelation where the base function is also called.
         *   During both specialized + base set of operations, it is desired to have the lock on this mutex.
         */
        mutable std::recursive_mutex myCompositeMutex;
};

#endif // COMPOSITEENTITYENGINE_H

