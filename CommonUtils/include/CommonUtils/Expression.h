#ifndef EXPRESSION_H
#define EXPRESSION_H

#include <string>
#include <deque>

#include "CommonUtils/ExpressionHelpers.h"

/**
 * @brief This class provides the ability to perform calculations on a given
 *        mathematical expression specified in infix notation.
 *        The expression may contain incognito values where is possible
 *        to set those variables over time and re-calculate.
 *
 *        Internally, this class will parse the infix expression and produces an postfix/RPN expression
 *        using the shunting-yard algorithm, so the expression evaluation could be performed.
 */
class Expression
{
    public:
        /**
         * @brief Deleted constructor
         */
        Expression() = delete;

        /**
         * @brief Construct a new Expression object from a given infix expression.
         *        In case the infix expression have syntax errors (i.e. missing parenthesis)
         *        runtime_error exception will be thrown.
         * @param infixExpression the mathematical expression given in infix notation
         */
        explicit Expression(const std::string& infixExpression);

        /**
         * @brief Destroy the Expression object
         */
        ~Expression() = default;

        /**
         * @brief Set a value for the incognito variable specified in the infix expression.
         * @param symbol the symbol that represents the incognito variable in the expression
         * @param value  the value to be assigned
         */
        void setOperandVariable(const std::string& symbol, const double& value);

        /**
         * @brief Insert a value, uniquely identified by given valueId, for the incognito variable specified in the infix expression.
         *        This way, an incognito variable may store several values and one can operate those values
         *        by using the available operators e.g. #AND, #OR, and #SUM (@see ExpressionHelpers.cpp)
         * @param symbol the symbol that represents the incognito variable in the expression
         * @param value  the value to be assigned
         */
        void setOperandVariableMultiValue(const std::string& symbol, const std::string& valueId, const double& value);

        /**
         * @brief Evaluate the expression and return calculated value.
         * @return double the result of the expression evaluation
         */
        double evaluate();

        /**
         * @brief Evaluate the expression and return calculated value, casted to bool.
         * @return false in case expression is evaluated equal 0; true otherwise
         */
        bool evaluateBool();

        /**
         * @brief Get the string with the expression in infix notation
         * @return std::string expression in infix notation
         */
        std::string getInfixExpression() const;

        /**
         * @brief Get the string with expression both represented in infix and postfix notation with evaluated value
         * @return std::string expression info
         */
        std::string to_string() const;

    private:
        std::string myInfixExpression; ///< String with the expression in infix notation
        /// The sequence of expression tokens that represents RPN form
        std::deque<ExpressionHelpers::ExpressionToken> myRpnExpressionSequence;
};

#endif /* EXPRESSION_H */
