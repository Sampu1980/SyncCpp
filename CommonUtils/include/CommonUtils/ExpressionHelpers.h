#ifndef EXPRESSION_HELPERS_H
#define EXPRESSION_HELPERS_H

#include <string>
#include <vector>
#include <deque>
#include <map>

namespace ExpressionHelpers
{
    /**
     * @brief Describes the token type,
     *        whether it is an operand or an operator
     *
     */
    enum class TokenType
    {
        OPERAND = 0,
        OPERATOR,

        INVALID
    };

    /**
     * @brief Determines how operators of the same precedence are
     *        grouped in the absence of parentheses.
     *  Left-associative: meaning the operations are grouped from the left
     *  Right-associative: meaning the operations are grouped from the right
     */
    enum class OperatorAssociativityType
    {
        LEFT = 0,
        RIGHT,
    };

    /**
     * @brief Comparison factor between two operators
     *        determining which one shall perform first in order
     *        to evaluate a given mathematical expression.
     */
    enum class PrecedenceType
    {
        EQUAL = 0,
        HIGHER,
        LOWER
    };

    /**
     * @brief Represents an expression token including:
     * - whether the token represents an operator or an operand (the type)
     * - a string representing the symbol in the expression
     * - the value that the symbol represents
     *
     * The symbol may be a value (i.e. '6': both symbol and value will be 6) or
     * can be an incognito variable
     * (i.e. 'X', symbol will be the 'X' and value will be defaulted as 0 and can later be set)
     */
    struct ExpressionToken
    {
        /**
         * @brief Default constructor
         */
        ExpressionToken()
            : type(TokenType::INVALID)
            , symbol("")
            , value(0)
        {
        }

        /**
         * @brief Construct a new Expression Token object
         *
         * @param pType type of the token in the expression
         * @param pSymbol string representing the token in the expression
         */
        ExpressionToken(const TokenType& pType, const std::string& pSymbol)
            : type(pType)
            , symbol(pSymbol)
            , value(0)
        {
        }

        /**
         * @brief Construct a new Expression Token object
         *
         * @param pType type of the token in the expression
         * @param pSymbol string representing the token in the expression
         * @param pVal value representing the token in the expression
         */
        ExpressionToken(const TokenType& pType, const std::string& pSymbol, const double& pVal)
            : type(pType)
            , symbol(pSymbol)
            , value(pVal)
        {
        }

        TokenType type; ///< Determines the type of the token, whether it is OPERAND or an OPERATOR
        std::string symbol; ///< String representing the token in the expression
        double value; ///< Value representing the token in the expression
        /// Container that holds the several values that represents the token in the expression
        std::map<std::string, double> multiValue;
    };

    /**
     * @brief Parse an infix expression string into several tokens strings,
     *        including operators, operands and parentheses.
     *        All white spaces will be discarted and this function will looks
     *        for operators, operands and parentheses in the process to split
     *        into several tokens. All can be mixed together without the need to
     *        be separated by whitespaces.
     *
     * @param expression mathematical expression in infix notation
     * @return std::vector<std::string> the several tokens parsed from the expression
     */
    std::vector<std::string> parseExpressionToTokens(const std::string& expression);

    /**
     * @brief Converts an expression from infix notation to postfix/RPN (Reverse Polish Notation)
     *        using the shunting-yard algorithm.
     *
     * @param inputTokens sequence of tokens that represents the infix expression
     * @param outRpnExpressionSequence the sequence of tokens that will represent the postfix/RPN expression
     * @return true in case conversion was sucessful; false otherwise
     */
    bool infixToRpnExpression(const std::vector<std::string>& inputTokens,
                              std::deque<ExpressionToken>& outRpnExpressionSequence);

    /**
     * @brief Evaluates the result value of a postfix/RPN (Reverse Polish Notation) expression.
     *        The algorithm to compute the RPN expression uses a stack where
     *        one goes through the tokens by pushing each operand on the stack while
     *        operators cause two items to be popped off the stack,
     *        evaluated and the result pushed back on the stack.
     *        Lastly, the one element left in the stack is the final result.
     *
     * @param rpnExpressionSequence sequence of tokens that represents the postfix/RPN expression expression
     * @return double the result value evaluated from the expression
     */
    double rpnExpressionToDouble(const std::deque<ExpressionToken>& rpnExpressionSequence);
};

#endif /* EXPRESSION_HELPERS_H */
