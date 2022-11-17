#include "gtest/gtest.h"
#include "CommonUtils/Utils.h"
#include "CommonUtils/ExpressionHelpers.h"
#include "CommonUtils/Expression.h"
#include "CommonUtils/RecursiveSharedMutex.h"

class CommonUtilsTest : public ::testing::Test
{
    public:
        CommonUtilsTest() = default;
        virtual ~CommonUtilsTest() = default;
    protected:
        void testParseTimeString(uint64_t expected, std::string iso8601String);
        void testParseTimeString(std::string expected, std::string iso8601String);
        void testParseTimeOnlyString(std::string expected, std::string timeString);
};

void CommonUtilsTest::testParseTimeString(std::string expected, std::string iso8601String)
{
    std::string result;
    std::chrono::system_clock::time_point result_tp;

    EXPECT_NO_THROW(result_tp = commonUtils::getTimePointFromIso8601Time(iso8601String));
    result = commonUtils::convertToISO8601TimeUTC(result_tp);
    EXPECT_EQ(result, expected);
}

void CommonUtilsTest::testParseTimeString(uint64_t expected, std::string iso8601String)
{
    uint64_t result;
    std::chrono::system_clock::time_point result_tp;

    EXPECT_NO_THROW(result_tp = commonUtils::getTimePointFromIso8601Time(iso8601String));
    result = std::chrono::duration_cast<std::chrono::seconds>(result_tp.time_since_epoch()).count();
    EXPECT_EQ(result, expected);
}

TEST_F(CommonUtilsTest, parseTimeStrings)
{
    testParseTimeString(1621956480, "2021-05-25T15:28:00Z");
    testParseTimeString(1653492491, "2022-05-25T15:28:11.222222Z");
    testParseTimeString(1685028491, "2023-05-25T15:28:11.222Z");
    testParseTimeString(1716636491, "2024-05-25T07:28:11.123-04:00");
    testParseTimeString(1716632891, "2024-05-25T05:28:11-05:00");
    testParseTimeString(1716672491, "2024-05-26T03:28:11.123456+06:00");
    testParseTimeString(1609962665, "2021-01-07T01:21:05+05:30");
    testParseTimeString(1609962665, "2021-01-06T19:51:05+00:00");
    testParseTimeString("2021-01-06T19:51:05Z", "2021-01-06T19:51:05+00:00");
    testParseTimeString("2021-02-06T12:00:05Z", "2021-02-06T17:30:05+05:30");
    // Test correct date 29th of February on leap year
    EXPECT_NO_THROW(commonUtils::getTimePointFromIso8601Time("2020-02-29T01:02:03Z"));
    // Test wrong date 29th of February on non-leap year
    EXPECT_THROW(commonUtils::getTimePointFromIso8601Time("2021-02-29T12:00:05Z"), std::runtime_error);
    // Test wrong date 30th of February
    EXPECT_THROW(commonUtils::getTimePointFromIso8601Time("2020-02-30T01:02:03Z"), std::runtime_error);
    // Test wrong date 32nd of January
    EXPECT_THROW(commonUtils::getTimePointFromIso8601Time("2021-01-32T12:00:05Z"), std::runtime_error);
    // Test wrong date 31st of April
    EXPECT_THROW(commonUtils::getTimePointFromIso8601Time("2021-04-31T01:02:00Z"), std::runtime_error);
    // Test wrong month, should be (0-12)
    EXPECT_THROW(commonUtils::getTimePointFromIso8601Time("2021-13-01T01:02:03Z"), std::runtime_error);
    // Test wrong hour, should be (0-23)
    EXPECT_THROW(commonUtils::getTimePointFromIso8601Time("2021-01-31T24:00:05Z"), std::runtime_error);
    // Test wrong minute, should be (0-59)
    EXPECT_THROW(commonUtils::getTimePointFromIso8601Time("2021-01-31T01:60:05Z"), std::runtime_error);
    // Test wrong second, should be (0-59)
    EXPECT_THROW(commonUtils::getTimePointFromIso8601Time("2021-12-31T01:02:60Z"), std::runtime_error);
}

void CommonUtilsTest::testParseTimeOnlyString(std::string expected, std::string timeString)
{
    std::chrono::system_clock::time_point result_tp;
    EXPECT_NO_THROW(result_tp = commonUtils::getTimePointFromTimeOnly(timeString));
    const std::time_t t_c = std::chrono::system_clock::to_time_t(result_tp);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&t_c), "%T");
    std::string result = ss.str();
    EXPECT_EQ(result, expected);
}

TEST_F(CommonUtilsTest, parseTimeOnlyStrings)
{
    testParseTimeOnlyString("23:59:00", "23:59");
    testParseTimeOnlyString("03:28:11", "03:28:11");
    testParseTimeOnlyString("00:00:00", "00:00");

    // Test invalid hours input
    EXPECT_THROW(commonUtils::getTimePointFromTimeOnly("24:00"), std::runtime_error);
    // Test invalid minutes input
    EXPECT_THROW(commonUtils::getTimePointFromTimeOnly("00:60"), std::runtime_error);
    // Test invalid seconds input
    EXPECT_THROW(commonUtils::getTimePointFromTimeOnly("00:00:60"), std::runtime_error);
}

TEST_F(CommonUtilsTest, parseTimePeriods)
{
    unsigned result;

    unsigned expected = 1;
    EXPECT_NO_THROW(result = commonUtils::getTimeIntervalInSecondsFromString("1s"));
    EXPECT_EQ(result, expected);

    expected = 122;
    EXPECT_NO_THROW(result = commonUtils::getTimeIntervalInSecondsFromString("2s 2m"));
    EXPECT_EQ(result, expected);

    expected = 123;
    EXPECT_NO_THROW(result = commonUtils::getTimeIntervalInSecondsFromString("     3s     2m"));
    EXPECT_EQ(result, expected);

    expected = 3784;
    EXPECT_NO_THROW(result = commonUtils::getTimeIntervalInSecondsFromString("3m   4s  1h"));
    EXPECT_EQ(result, expected);

    expected = 353665;
    EXPECT_NO_THROW(result = commonUtils::getTimeIntervalInSecondsFromString("14m   25s  2h  4d"));
    EXPECT_EQ(result, expected);

    expected = 1224000;
    EXPECT_NO_THROW(result = commonUtils::getTimeIntervalInSecondsFromString("2w 4h"));
    EXPECT_EQ(result, expected);
}

TEST_F(CommonUtilsTest, testRecursiveSharedMutex)
{
    bool testFinished = false;

    // ////////////////////////////////////////////
    // Test mutex starting with shared lock
    // ////////////////////////////////////////////

    std::thread threadTestStartShared([&testFinished]
    {
        RecursiveSharedMutex myMutexStartShared;

        std::shared_lock<RecursiveSharedMutex> lock1(myMutexStartShared);
        std::shared_lock<RecursiveSharedMutex> lock2(myMutexStartShared);
        std::lock_guard<RecursiveSharedMutex>  lock3(myMutexStartShared);
        std::lock_guard<RecursiveSharedMutex>  lock4(myMutexStartShared);
        std::shared_lock<RecursiveSharedMutex> lock5(myMutexStartShared);
        std::shared_lock<RecursiveSharedMutex> lock6(myMutexStartShared);

        testFinished = true;
    });
    threadTestStartShared.detach();

    // Give some time to thread be finished
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_TRUE(testFinished);

    // ////////////////////////////////////////////
    // Test mutex starting with exclusive lock
    // ////////////////////////////////////////////

    testFinished = false;

    std::thread threadTestStartExclusive([&testFinished]
    {
        RecursiveSharedMutex myMutexStartExclusive;

        std::lock_guard<RecursiveSharedMutex>  lock1(myMutexStartExclusive);
        std::lock_guard<RecursiveSharedMutex>  lock2(myMutexStartExclusive);
        std::shared_lock<RecursiveSharedMutex> lock3(myMutexStartExclusive);
        std::shared_lock<RecursiveSharedMutex> lock4(myMutexStartExclusive);
        std::lock_guard<RecursiveSharedMutex>  lock5(myMutexStartExclusive);
        std::shared_lock<RecursiveSharedMutex> lock6(myMutexStartExclusive);
        std::shared_lock<RecursiveSharedMutex> lock7(myMutexStartExclusive);

        testFinished = true;
    });
    threadTestStartExclusive.detach();

    // Give some time to thread be finished
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_TRUE(testFinished);
}

TEST_F(CommonUtilsTest, testExpression)
{
    std::string expressionTestStr = "(x && y || (z && b)) && !b";

    Expression rpnExpression(expressionTestStr);

    // (1 & 1 | (0 & 0)) & !0 => 1
    rpnExpression.setOperandVariable({"x"}, 1);
    rpnExpression.setOperandVariable({"y"}, 1);
    rpnExpression.setOperandVariable({"z"}, 0);
    rpnExpression.setOperandVariable({"b"}, 0);
    EXPECT_EQ(rpnExpression.evaluate(), 1.0);
    EXPECT_TRUE(rpnExpression.evaluateBool());

    // (1 & 1 | (0 & 1)) & !1 => 1
    rpnExpression.setOperandVariable({"b"}, 1);
    EXPECT_EQ(rpnExpression.evaluate(), 0.0);
    EXPECT_FALSE(rpnExpression.evaluateBool());
}

TEST_F(CommonUtilsTest, testExpressionSetVariableSeveralTimes)
{
    std::string expressionTestStr = "1+2+X+4";

    Expression rpnExpression(expressionTestStr);

    EXPECT_EQ(rpnExpression.evaluate(), 7.0);

    rpnExpression.setOperandVariable({"X"}, 3);
    EXPECT_EQ(rpnExpression.evaluate(), 10.0);
}

TEST_F(CommonUtilsTest, testExpressionParenthesis)
{
    std::string expressionTestStr = "(1 AND 0) OR 1";

    Expression rpnExpression(expressionTestStr);

    EXPECT_TRUE(rpnExpression.evaluateBool());
}

TEST_F(CommonUtilsTest, testExpressionWithDifferentPrecedences)
{
    std::string expressionTestStr = "1 + 2 * 2";

    Expression rpnExpression(expressionTestStr);

    EXPECT_EQ(rpnExpression.evaluate(), 5.0);
}

TEST_F(CommonUtilsTest, testExpressionMissingParenthesis)
{
    EXPECT_THROW(Expression("(1 + 2 * 9"), std::exception); // Missing parenthesis
    EXPECT_THROW(Expression("1 + 2) * 9"), std::exception); // Missing parenthesis
    EXPECT_NO_THROW(Expression("(1 + 2) * 9")); // Fixed parenthesis

    EXPECT_THROW(Expression("(1 + 2) * ((9+9)/ (12+6)"), std::exception); // Missing parenthesis
    EXPECT_NO_THROW(Expression("(1 + 2) * ((9+9)/ (12+6))")); // Missing parenthesis
}

TEST_F(CommonUtilsTest, testExpressionMultiValuesAnded)
{
    std::string expressionTestStr = "#AND(X)";

    Expression rpnExpression(expressionTestStr);

    rpnExpression.setOperandVariableMultiValue({"X"}, "A", 1);

    double res = rpnExpression.evaluate();

    EXPECT_EQ(res, 1.0);
    EXPECT_TRUE(rpnExpression.evaluateBool());

    rpnExpression.setOperandVariableMultiValue({"X"}, "B", 0);

    res = rpnExpression.evaluate();
    EXPECT_EQ(res, 0.0);
    EXPECT_FALSE(rpnExpression.evaluateBool());

    rpnExpression.setOperandVariableMultiValue({"X"}, "B", 1);

    res = rpnExpression.evaluate();

    EXPECT_EQ(res, 1.0);
    EXPECT_TRUE(rpnExpression.evaluateBool());
}

TEST_F(CommonUtilsTest, testExpressionMultiValuesOred)
{
    std::string expressionTestStr = "#OR(X)";

    Expression rpnExpression(expressionTestStr);

    rpnExpression.setOperandVariableMultiValue({"X"}, "A", 0);
    rpnExpression.setOperandVariableMultiValue({"X"}, "B", 0);

    double res = rpnExpression.evaluate();
    EXPECT_EQ(res, 0.0);
    EXPECT_FALSE(rpnExpression.evaluateBool());

    rpnExpression.setOperandVariableMultiValue({"X"}, "B", 1);

    res = rpnExpression.evaluate();

    EXPECT_EQ(res, 1.0);
    EXPECT_TRUE(rpnExpression.evaluateBool());
}

TEST_F(CommonUtilsTest, testExpressionSumMultiValue)
{
    std::string expressionTestStr = "#SUM(X)";

    Expression rpnExpression(expressionTestStr);

    rpnExpression.setOperandVariableMultiValue({"X"}, "A", 1);
    rpnExpression.setOperandVariableMultiValue({"X"}, "B", 9);

    double res = rpnExpression.evaluate();

    EXPECT_EQ(res, 10.0);
}
