#include <stdexcept>

#include "CommonUtils/Expression.h"

using namespace ExpressionHelpers;

Expression::Expression(const std::string& infixExpression)
    : myInfixExpression(infixExpression)
{
    // Split the expression into single tokens
    std::vector<std::string> tokens = parseExpressionToTokens(myInfixExpression);

    // Evaluate expression and convert from infix to RPN format
    std::deque<ExpressionToken> expressionTokens;

    if(infixToRpnExpression(tokens, expressionTokens))
    {
        for(const auto& token : expressionTokens)
        {
            myRpnExpressionSequence.push_back(token);
        }
    }
    else
    {
        throw std::runtime_error("Expression syntax fail: " + myInfixExpression);
    }
}

void Expression::setOperandVariable(const std::string& symbol, const double& value)
{
    for(auto& token : myRpnExpressionSequence)
    {
        if(TokenType::OPERAND == token.type && symbol == token.symbol)
        {
            token.value = value;
            // DO NOT BREAK LOOP HERE! the symbol may be found multiple times in the expression!
        }
    }
}

void Expression::setOperandVariableMultiValue(const std::string& symbol, const std::string& valueId,
                                              const double& value)
{
    for(auto& token : myRpnExpressionSequence)
    {
        if(TokenType::OPERAND == token.type && symbol == token.symbol)
        {
            token.multiValue[valueId] = value;
            // DO NOT BREAK LOOP HERE! the symbol may be found multiple times in the expression!
        }
    }
}

double Expression::evaluate()
{
    return rpnExpressionToDouble(myRpnExpressionSequence);
}

bool Expression::evaluateBool()
{
    return static_cast<bool>(rpnExpressionToDouble(myRpnExpressionSequence));
}

std::string Expression::getInfixExpression() const
{
    return myInfixExpression;
}

std::string Expression::to_string() const
{
    std::string out;
    out.append("Infix: ");
    out.append(myInfixExpression);
    out.append(" || (Postfix)RPN: ");

    for(const auto& token : myRpnExpressionSequence)
    {
        out.append(token.symbol);

        if(TokenType::OPERAND == token.type)
        {
            out.append("[");

            if(token.multiValue.empty())
            {
                out.append(std::to_string(token.value));
            }
            else
            {
                for(const auto& iterValue : token.multiValue)
                {
                    out.append(std::to_string(iterValue.second));
                    out.append(" ");
                }
            }

            out.append("]");
        }

        out.append(" ");
    }

    return out;
}
