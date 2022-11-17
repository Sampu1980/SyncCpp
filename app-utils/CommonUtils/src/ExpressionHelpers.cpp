#include <sstream>
#include <cstdlib>
#include <list>
#include <stack>
#include <map>
#include <deque>
#include <functional>
#include <tuple>

#include "CommonUtils/ExpressionHelpers.h"

namespace ExpressionHelpers
{
    typedef std::function<double (ExpressionToken& v1, ExpressionToken& v2)> OperatorFunctionType;

    // *INDENT-OFF*
    /**
     * @brief Describe the supported operators, including some characteristics:
     * > Precedence: determines which procedures to perform first in order to evaluate a given mathematical expression
     * > Associativity: determines how operators of the same precedence are grouped in the absence of parentheses
     * > Implementation: code that perform desired operator calculation
     *
     * Next values for the Precedence and Associativity was based on the same values used on C/C++ language.
     *  => A Lower value means Higher precedence
     *
     */
    static const std::map<std::string, std::tuple<int, OperatorAssociativityType, OperatorFunctionType>> gOperatorInfo
    {
    //  |------------------------------------------------------------------------------------------|
    //  | OPERATOR | PRECEDENCE | ASSOCIATIVITY                   | OPERATOR IMPLEMENTATION LAMBDA |
    //  | (string) | (int)      | (OperatorAssociativityType)     | (function)
    //  |------------------------------------------------------------------------------------------|
        { "+",     { 6,           OperatorAssociativityType::LEFT,  [](ExpressionToken& v1, ExpressionToken& v2) { return v1.value + v2.value; }} },
        { "-",     { 6,           OperatorAssociativityType::LEFT,  [](ExpressionToken& v1, ExpressionToken& v2) { return v1.value - v2.value; }} },
        { "*",     { 5,           OperatorAssociativityType::LEFT,  [](ExpressionToken& v1, ExpressionToken& v2) { return v1.value * v2.value; }} },
        { "/",     { 5,           OperatorAssociativityType::LEFT,  [](ExpressionToken& v1, ExpressionToken& v2) { return v1.value / v2.value; }} },
        { "&&",    { 14,          OperatorAssociativityType::LEFT,  [](ExpressionToken& v1, ExpressionToken& v2) { return v1.value && v2.value; }} },
        { "||",    { 15,          OperatorAssociativityType::LEFT,  [](ExpressionToken& v1, ExpressionToken& v2) { return v1.value || v2.value; }} },
        { "AND",   { 14,          OperatorAssociativityType::LEFT,  [](ExpressionToken& v1, ExpressionToken& v2) { return v1.value && v2.value; }} },
        { "OR",    { 15,          OperatorAssociativityType::LEFT,  [](ExpressionToken& v1, ExpressionToken& v2) { return v1.value || v2.value; }} },
        { "!",     { 3,           OperatorAssociativityType::RIGHT, [](ExpressionToken& v1, ExpressionToken& v2) { return !v1.value;      }} },
        // Perform the AND operation over all values that operand holds (multi-value storage)
        { "#AND",  { 3,           OperatorAssociativityType::RIGHT,
        [](ExpressionToken& v1, ExpressionToken& v2)
        {
            // Use a default value of 1.0 when at least one value is in storage,
            // so the first AND operation is neutral
            double res = v1.multiValue.empty() ? 0.0 : 1.0;
            for(const auto& it : v1.multiValue)
            {
                const double& value = it.second;
                res = res && value;
            }
            return res;
        }}},
        // Perform the OR operation over all values that operand holds (multi-value storage)
        { "#OR",  { 3,           OperatorAssociativityType::RIGHT,
        [](ExpressionToken& v1, ExpressionToken& v2)
        {
            double res = 0.0;
            for(const auto& it : v1.multiValue)
            {
                const double& value = it.second;
                res = res || value;
            }
            return res;
        }}},
        // Perform the SUM operation from all values that operand holds (multi-value storage)
        { "#SUM",  { 3,           OperatorAssociativityType::RIGHT,
        [](ExpressionToken& v1, ExpressionToken& v2)
        {
            double res = 0.0;
            for(const auto& it : v1.multiValue)
            {
                const double& value = it.second;
                res += value;
            }
            return res;
        }}},
    };
    // *INDENT-ON*

    /**
     * @brief Test if symbol is a parenthesis
     *
     * @param symbol the symbol to be tested
     * @return true if it is a parenthesis; false otherwise
     */
    bool isParenthesis(const std::string& symbol)
    {
        return symbol == "(" || symbol == ")";
    }

    /**
     * @brief Test if symbol is any of the supported operators
     * @see gOperatorInfo
     * @param symbol the symbol to be tested
     * @return true if it is an operator; false otherwise
     */
    bool isOperator(const std::string& symbol)
    {
        return (gOperatorInfo.find(symbol) != gOperatorInfo.end());
    }

    /**
     * @brief Test associativity of the given operator
     *
     * @param operator the operator under test
     * @param type the associativity to be tested
     * @return true in case given associativity matches the operator; false otherwise
     */
    bool isAssociative(const std::string& operatorSymbol, const OperatorAssociativityType& type)
    {
        // The operator info is a tuple where at position 1 we have the operator associativity
        const OperatorAssociativityType tokenAssociativity = std::get<1>(gOperatorInfo.find(operatorSymbol)->second);
        return (tokenAssociativity == type);
    }

    /**
     * @brief Test precedence between given operators op1 and op2.
     *
     * @param op1 the operator under test
     * @param op2 the operator to compare with
     * @return PrecedenceType one of the following values:
     *         EQUAL   => equal precedence
     *         HIGHER  => op1 has higher precedence than op2
     *         LOWER   => op1 has lower precedence than op2
     */
    PrecedenceType precedence(const std::string& op1, const std::string& op2)
    {
        const int p1 = std::get<0>(gOperatorInfo.find(op1)->second);
        const int p2 = std::get<0>(gOperatorInfo.find(op2)->second);

        return (p1 == p2 ? PrecedenceType::EQUAL  :
                p1 < p2  ? PrecedenceType::HIGHER : // A lowest value has highest priority
                PrecedenceType::LOWER);
    }

    std::vector<std::string> parseExpressionToTokens(const std::string& expression)
    {
        std::vector<std::string> tokens;
        std::string str = "";

        for(int i = 0; i < expression.length(); ++i)
        {
            const std::string token(1, expression[i]);

            if(isOperator(token) || isParenthesis(token))
            {
                if(false == str.empty())
                {
                    tokens.push_back(str);
                }

                str = "";
                tokens.push_back(token);
            }
            else
            {
                // Append the numbers
                if(false == token.empty() && token != " ")
                {
                    str.append(token);
                }
                else
                {
                    if(false == str.empty())
                    {
                        tokens.push_back(str);
                        str = "";
                    }
                }
            }
        }

        // Store the last operand
        if(false == str.empty())
        {
            tokens.push_back(str);
        }

        return tokens;
    }

    bool infixToRpnExpression(const std::vector<std::string>& inputTokens,
                              std::deque<ExpressionToken>& outRpnExpressionSequence)
    {
        std::stack<std::string> stack;

        // While there are tokens to be read
        for(const std::string& token : inputTokens)
        {
            // If token is an operator
            if(isOperator(token))
            {
                // While there is an operator token, o2, at the top of the stack AND
                // either o1 is left-associative AND its precedence is equal to that of o2,
                // OR o1 has precedence less than that of o2,
                const std::string& o1 = token;

                if(!stack.empty())
                {
                    std::string o2 = stack.top();

                    while(isOperator(o2) &&
                          ((isAssociative(o1, OperatorAssociativityType::LEFT) && PrecedenceType::EQUAL == precedence(o1, o2)) ||
                           (PrecedenceType::LOWER == precedence(o1, o2))))
                    {
                        // pop o2 off the stack, into the output queue;
                        stack.pop();
                        outRpnExpressionSequence.push_back({TokenType::OPERATOR, o2});

                        if(!stack.empty())
                        {
                            o2 = stack.top();
                        }
                        else
                        {
                            break;
                        }
                    }
                }

                // push o1 into the stack.
                stack.push(o1);
            }
            // If the token is a left parenthesis, then push it into the stack.
            else if(token == "(")
            {
                // Push token to top of the stack
                stack.push(token);
            }
            // If token is a right parenthesis
            else if(token == ")")
            {
                std::string topToken  = stack.top();

                // While the operator at the top of the operator stack is not a left parenthesis
                while(topToken != "(")
                {
                    // Pop the operator from the operator stack into the output queue
                    ExpressionToken tk{TokenType::OPERATOR, topToken};
                    outRpnExpressionSequence.push_back(tk);
                    stack.pop();

                    // The operator stack MUST not be empty at this point otherwise
                    // there are mismatched parentheses because a left parenthesis is missing
                    if(stack.empty())
                    {
                        return false;
                    }

                    topToken = stack.top();
                }

                // Pop the left parenthesis from the stack and discard it
                if(!stack.empty())
                {
                    stack.pop();
                }

                // If the stack runs out without finding a left parenthesis,
                // then there are mismatched parentheses
                if(topToken != "(")
                {
                    return false;
                }
            }
            // If the token is a number or incognito, then add it to the output queue.
            else
            {
                // Note that strtod returns 0 in case no conversion can be performed, which is what we want to use in that case!
                outRpnExpressionSequence.push_back(ExpressionToken{TokenType::OPERAND, token, std::strtod(token.c_str(), nullptr)});
            }
        }

        // While there are still operator tokens in the stack
        while(!stack.empty())
        {
            const std::string stackToken = stack.top();

            // If the operator token on the top of the stack is a parenthesis,
            // then there are mismatched parentheses.
            if(isParenthesis(stackToken))
            {
                return false;
            }

            // Pop the operator into the output queue
            ExpressionToken tk;
            tk.symbol = stackToken;

            if(isOperator(stackToken))
            {
                tk.type = TokenType::OPERATOR;
            }
            else
            {
                tk.type = TokenType::OPERAND;
            }

            outRpnExpressionSequence.push_back(tk);
            stack.pop();
        }

        return true;
    }

    double rpnExpressionToDouble(const std::deque<ExpressionToken>& rpnExpressionSequence)
    {
        std::stack<ExpressionToken> stack;

        for(const ExpressionToken& token : rpnExpressionSequence)
        {
            // Token is OPERAND
            if(TokenType::OPERAND == token.type)
            {
                // Push it into the stack
                stack.push(token);
            }
            // Token is OPERATOR
            else
            {
                double result =  0.0;

                // Token has right hand associativity
                if(isAssociative(token.symbol, OperatorAssociativityType::RIGHT))
                {
                    // Pop top entry
                    ExpressionToken val = stack.top();
                    stack.pop();
                    ExpressionToken dummy;
                    result = std::get<2>(gOperatorInfo.find(token.symbol)->second)(val, dummy);
                }
                // Token is other kind of operator
                else
                {
                    // Pop top two entries
                    ExpressionToken d2 = stack.top();
                    stack.pop();

                    if(!stack.empty())
                    {
                        ExpressionToken d1 = stack.top();
                        stack.pop();

                        // Calculate the result
                        result = std::get<2>(gOperatorInfo.find(token.symbol)->second)(d1, d2);
                    }
                    else
                    {
                        if(token.symbol == "-")
                        {
                            result = d2.value * -1;
                        }
                        else
                        {
                            result = d2.value;
                        }
                    }
                }

                // Push result into stack
                std::ostringstream s;
                s << result;
                ExpressionToken resultTk(TokenType::OPERAND, s.str(), result);
                stack.push(resultTk);
            }
        }

        return stack.top().value;
    }

} // END namespace
