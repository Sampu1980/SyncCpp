#include <sstream>
#include <algorithm>
#include <iostream>
#include <typeinfo>
#include <boost/functional/hash.hpp>
#include "gtest/gtest.h"
#include "CommonUtils/BaseGraph.h"

//TODO NC: This UT need to be refactored.
// The idea was to test a graph having node with keys of different implementations:
//
//      root node
//      /
//    MoKey
//     /
//   FaultKey
//
// The main purpose was to test the ability to run DFS and cast the node key to the specialized one,
// and validade no error occurred. Currently, this was done but validaded by printing to console.
// The refactor include to do same approach but using google test macros

// Custom Keys

class MoKey : public Key
{
    public:
        class MoKeyHasher
        {
            public:
                std::size_t operator()(const MoKey& key) const noexcept
                {
                    std::size_t hashSeed = 0;
                    boost::hash_combine(hashSeed, boost::hash_value(key.getEntity()));

                    return hashSeed;
                }
        };

        MoKey()
            : Key() {}
        MoKey(const std::string& entity, const std::string& type)
            : Key(entity, type) {}
        MoKey(const Key& key)
            : Key(key) {}
        MoKey(const Key& aKey, const std::string& aType)
            : Key(aKey, aType) {}
        ~MoKey() = default;

        virtual std::size_t calculatePolymorphicHash() const noexcept override
        {
            return MoKeyHasher{}.operator()(*this);
        }
};

class FaultKey : public MoKey
{
    public:
        class FaultKeyHasher
        {
            public:
                std::size_t operator()(const FaultKey& key) const noexcept
                {
                    std::size_t hashSeed = 0;
                    boost::hash_combine(hashSeed, boost::hash_value(key.getEntity()));
                    boost::hash_combine(hashSeed, boost::hash_value(key.getType()));
                    boost::hash_combine(hashSeed, boost::hash_value(static_cast<int>(key.getLocation())));
                    boost::hash_combine(hashSeed, boost::hash_value(static_cast<int>(key.getDirection())));

                    return hashSeed;
                }
        };

        FaultKey()
            : MoKey()
            , myLocation(0)
            , myDirection(0) {}
        FaultKey(const std::string& entity, const std::string& type,
                 const int location, const int direction)
            : MoKey(entity, type)
            , myLocation(location)
            , myDirection(direction) {};
        ~FaultKey() = default;

        virtual std::size_t calculatePolymorphicHash() const noexcept override
        {
            return FaultKeyHasher{}.operator()(*this);
        }


        int getLocation() const
        {
            return myLocation;
        }

        int getDirection() const
        {
            return myDirection;
        }

    private:
        int myLocation;
        int myDirection;
};

class CustomGraphDfsVisitor : public BaseGraphDfsVisitorInterface<BaseNode>
{
    public:
        CustomGraphDfsVisitor()
            : visitedNodeKeyVector(new std::vector<Key>())
            , visitedNodeVector(new std::vector<BaseNode>())
        {};

        ~CustomGraphDfsVisitor()
        {
            visitedNodeKeyVector->clear();
            visitedNodeVector->clear();
        };

        std::vector<Key>& getVisitedNodesKey() const
        {
            return *visitedNodeKeyVector;
        }

        std::vector<BaseNode>& getVisitedNodes() const
        {
            return *visitedNodeVector;
        }

        // BaseGraphDfsVisitorInterface implementation
        void onStartNode(const Key& nodeKey, const BaseNode& node) const override
        {
            visitedNodeKeyVector->clear();
            visitedNodeVector->clear();
        };

        void onDiscoverNode(const bool& startNode, const Key& nodeKey, const BaseNode& node) const override
        {
            try
            {
                auto& faultKey = dynamic_cast<const FaultKey&>(nodeKey);
                //std::cout << "onDiscoverNode Cast Key sucess:" << faultKey.getShortDescription()  << ", loc=" << faultKey.getLocation() << std::endl;
            }
            catch(std::exception const& e)
            {
                //std::cout << "=> onDiscoverNode : Failed to cast" << std::endl;
            }

            visitedNodeKeyVector->push_back(nodeKey);
            visitedNodeVector->push_back(node);
        };
        void onFinishNode(const Key& nodeKey, const BaseNode& node) const override {};

    private:
        boost::shared_ptr<std::vector<Key> > visitedNodeKeyVector;
        boost::shared_ptr<std::vector<BaseNode> > visitedNodeVector;
};

class MockBaseBidirectionalGraphCustomKey : public BaseGraph<BaseNode, BidirectionalGraphType>
{
    public:
        std::map<int, Key> myNodesMap;

        MockBaseBidirectionalGraphCustomKey()
            : BaseGraph()
        {};

        std::map<int, Key> getNodesMapping()
        {
            return myNodesMap;
        }

        std::vector<Key> getReachableNodesFrom(std::shared_ptr<Key> node)
        {
            std::vector<BaseNode> ret;

            CustomGraphDfsVisitor vis;

            runDfs(node, vis);

            return vis.getVisitedNodesKey();
        }

        std::vector<std::shared_ptr<Key>> getAdjacentNodes(std::shared_ptr<Key> node)
        {
            std::vector<std::shared_ptr<Key>> ret;

            InternalGraph::adjacency_iterator neighbourIt;
            InternalGraph::adjacency_iterator neighbourEnd;
            // boost::adjacent_vertices gives a std::pair<adjacency_iterator, adjacency_iterator>. Tie those to our iterators
            boost::tie(neighbourIt, neighbourEnd) = boost::adjacent_vertices(myBiMappingOfNodeDescriptorAndKey.right.at(node),
                                                                             myGraph);

            for(; neighbourIt != neighbourEnd; ++neighbourIt)
            {
                // dereference neighbourIt, get the vertice_descriptor
                ret.push_back(myBiMappingOfNodeDescriptorAndKey.left.at(*neighbourIt));
            }

            return ret;
        }
};

// Validate DFS algorithm
TEST(BaseGraphCustomKeyTestTest, NodesWithDifferentKeyTypes1)
{
    MockBaseBidirectionalGraphCustomKey myGraph;

    std::shared_ptr<MoKey> chm6Key(std::make_shared<MoKey>("chm6_entity", "chm6"));
    std::shared_ptr<FaultKey> chm6FaultIMPROPKey(std::make_shared<FaultKey>("chm6_entity", "EQPTFAIL", 1, 1));
    std::shared_ptr<FaultKey> chm6FaultIMPROPKey2(std::make_shared<FaultKey>("chm6_entity", "EQPTFAIL", 2, 2));

    myGraph.createConnection(chm6Key, chm6FaultIMPROPKey);
    myGraph.createConnection(chm6FaultIMPROPKey, chm6FaultIMPROPKey2);

    std::vector<std::shared_ptr<Key>> adjadentFaultNode = myGraph.getAdjacentNodes(chm6FaultIMPROPKey);
    ASSERT_EQ(adjadentFaultNode.size(), 1) << "Number of chm6Key Adjacent Nodes NOT as expected!";

    try
    {
        const FaultKey& searchChm6FaultKey = dynamic_cast<const FaultKey&>(*adjadentFaultNode[0]);
    }
    catch(std::exception const& e)
    {
        ASSERT_TRUE(false) << "Unexpected exception when casting node of type Key to FaultKey";
    }

    myGraph.getReachableNodesFrom(chm6Key);

    myGraph.getReachableNodesFrom(chm6FaultIMPROPKey);

    myGraph.getReachableNodesFrom(chm6FaultIMPROPKey2);
}

// Validate DFS algorithm
TEST(BaseGraphCustomKeyTestTest, NodesWithDifferentKeyTypes2)
{
    MockBaseBidirectionalGraphCustomKey myGraph;

    std::shared_ptr<MoKey> chm6Key(std::make_shared<MoKey>("chm6_entity", "chm6"));
    std::shared_ptr<FaultKey> chm6FaultIMPROPKey(std::make_shared<FaultKey>("chm6_entity", "EQPTFAIL", 1, 1));
    std::shared_ptr<FaultKey> chm6FaultIMPROPKey2(std::make_shared<FaultKey>("chm6_entity", "EQPTFAIL", 2, 2));
    std::shared_ptr<FaultKey> chm6FaultIMPROPKey3(std::make_shared<FaultKey>("chm6_entity", "EQPTFAIL", 2, 2));

    myGraph.createConnection(chm6Key, chm6FaultIMPROPKey);
    myGraph.createConnection(chm6Key, chm6FaultIMPROPKey2);
    myGraph.createConnection(chm6FaultIMPROPKey2, chm6FaultIMPROPKey3);

    std::vector<std::shared_ptr<Key>> adjadentFaultNode = myGraph.getAdjacentNodes(chm6Key);
    ASSERT_EQ(adjadentFaultNode.size(), 2) << "Number of chm6Key Adjacent Nodes NOT as expected!";

    myGraph.deleteReachableNodesFrom(chm6FaultIMPROPKey);

    myGraph.getReachableNodesFrom(chm6Key);
}
