#include <sstream>
#include <iostream>
#include "gtest/gtest.h"
#include "CommonUtils/Key.h"
#include "CommonUtils/Utils.h"

// create a key, using several available constructors, and validate members are set consistently
TEST(KeyTest, KeyCreation)
{
    Key k("Entity_XXX", "Type_YYY");
    EXPECT_STREQ(k.getEntity().c_str(), "Entity_XXX") << " Attribute 'Entity' not correctly set.";
    EXPECT_STREQ(k.getType().c_str(),   "Type_YYY")   << " Attribute 'Type' not correctly set.";

    Key k_copy(k);
    EXPECT_STREQ(k.getEntity().c_str(), "Entity_XXX") << " Attribute 'Entity' not correctly set.";
    EXPECT_STREQ(k.getType().c_str(),   "Type_YYY")   << " Attribute 'Type' not correctly set.";

    Key k_newtype(k, "fault_1");
    EXPECT_STREQ(k_newtype.getEntity().c_str(), "Entity_XXX") << " Attribute 'Entity' not correctly set.";
    EXPECT_STREQ(k_newtype.getType().c_str(),   "fault_1")   << " Attribute 'Type' not correctly set.";
}

// create two keys and validate operator ==
TEST(KeyTest, KeyEqualComparition)
{
    Key k1("Entity_1", "Type_1");
    Key k1_copy("Entity_1", "Type_1");
    Key k2("Entity_2", "Type_2");

    EXPECT_TRUE(k1 == k1_copy) << " Objects k1 and k1_are not equal.";
    EXPECT_FALSE(k1 == k2)     << " Objects k1 and k2 are equal.";
}

// create two keys and validate operator !=
TEST(KeyTest, KeyNotEqualComparition)
{
    Key k1("Entity_1", "Type_1");
    Key k1_copy("Entity_1", "Type_1");
    Key k2("Entity_2", "Type_2");

    EXPECT_TRUE(k1 != k2)       << " Objects k1 and k2 are equal.";
    EXPECT_FALSE(k1 != k1_copy) << " Objects k1 and k1_are not equal.";
}

// create several keys and validate KeyHasher function correctly calculates the hash value
TEST(KeyTest, KeyHashGenerator)
{
    Key k1("Entity_1", "Type_1");
    Key k1_copy("Entity_1", "Type_1");
    Key k2("Entity_2", "Type_2");

    // Calculate the hash for each key object
    std::size_t hash_k1      = KeyHasher{}(k1);
    std::size_t hash_k1_copy = KeyHasher{}(k1);
    std::size_t hash_k2      = KeyHasher{}(k2);

    EXPECT_NE(hash_k1,      0) << " Generated hash equal to 0.";
    EXPECT_NE(hash_k1_copy, 0) << " Generated hash equal to 0.";
    EXPECT_NE(hash_k2,      0) << " Generated hash equal to 0.";

    ASSERT_TRUE(k1 == k1_copy)         << " Objects k1 and k1_copy are not equal.";
    EXPECT_EQ(hash_k1, hash_k1_copy) << " Generated hash for two equal objects not the same";

    ASSERT_FALSE(k1 == k2)             << " Objects k1 and k2 are equal.";
    EXPECT_NE(hash_k1, hash_k2)      << " Generated hash for two different objects the same";
}


