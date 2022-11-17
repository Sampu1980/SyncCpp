#ifndef EXPRESSIONENTITYENGINE_H
#define EXPRESSIONENTITYENGINE_H

#include "CommonUtils/CompositeEntityEngine.h"
#include "CommonUtils/Expression.h"

/**
 * @class ExpressionEntityEngine
 * @brief This class is responsible to manage the state of a composite entity
 *        where the state is determinated from a mathemathical expression.
 *
 *        The procedure to register composite entities and its members differs from
 *        the base function given by CompositeEntityEngine in the way that it is now necessary
 *        to give a math expression and identify the members as variable in the expression.
 * @see addCompositeRelation
 *
 * A composite entity has the following possible states:
 * -> IDLE : indicates that state is not determined yet (initial state);
 * -> CUSTOM_EXPRESSION_EVALUATED_FALSE : the associated expression is evaluated false and so composite entity is declared as not failed
 * -> CUSTOM_EXPRESSION_EVALUATED_TRUE  : the associated expression is evaluated true and so composite entity is declared as failed
 *
 * @see CompositeEntityState
 */
class ExpressionEntityEngine : public CompositeEntityEngine
{
    public:
        ExpressionEntityEngine() = delete;

        /**
         * @brief Constructor
         * @param callbackFunction callback function to be executed whenever the state of a composite entity changes.
         */
        explicit ExpressionEntityEngine(CompositeEntityCallbackFunctionType callbackFunction);

        /**
         * @brief Default destructor
         */
        ~ExpressionEntityEngine();

        /**
         * @brief Register the given compositeMemberMoKey as member of composite entity compositeMoKey.
         * @param compositeMoKey the composite entity key
         * @param evaluationStateExpression expression to be evaluated when determining the composite state
         * @param compositeMemberMoKey the composite member key
         * @param symbolInExpression string that identifies the member in the expression so it can be evaluated
         *        with its contributor state
         */
        void addCompositeRelation(std::shared_ptr<Key> compositeMoKey, const std::string& evaluationStateExpression,
                                  std::shared_ptr<Key> compositeMemberMoKey, const std::string& symbolInExpression);
        void deleteCompositeMember(std::shared_ptr<Key> compositeMemberMoKey) override;
        void deleteComposite(std::shared_ptr<Key> compositeMoKey) override;
        std::string toString() override;

        /**
         * @brief Look for the expression that is associated to the given composite entity.
         *
         * @param compositeEntity the composite entity key
         * @return std::string associated expression in string format
         */
        std::string getAssociatedExpression(std::shared_ptr<Key> compositeEntity) const;

    protected:
        void evaluateCompositeState(std::shared_ptr<Key> compositeEntity) override;

        /// Map defining a composite entity (key) and the related expression
        std::unordered_map<std::shared_ptr<Key>, Expression, PolymorphicKeyHasher> myCompositeExpressions;

        typedef std::unordered_map<std::shared_ptr<Key>, std::string, PolymorphicKeyHasher> AssociatedCompositeMap;
        /// Implements the following mapping: composite member (key) => associated composite entities symbols
        std::unordered_map<std::shared_ptr<Key>, AssociatedCompositeMap, PolymorphicKeyHasher> myMemberSymbolsMapping;
};

#endif // EXPRESSIONENTITYENGINE_H

