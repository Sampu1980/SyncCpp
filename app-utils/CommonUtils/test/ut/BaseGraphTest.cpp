#include <sstream>
#include <algorithm>
#include <memory>
#include "gtest/gtest.h"
#include "CommonUtils/BaseGraph.h"

enum GraphNodes {K1 = 0, K2, K3, K4, K5, K6, K_NUMBER};
int nodes[]                   = { K1,       K2,       K3,       K4,       K5,       K6 };
std::string NodeEntityNames[] = { "key_1",  "key_2",  "key_3",  "key_4",  "key_5",  "key_6" };
std::string NodeTypeNames[]   = { "type_1", "type_2", "type_3", "type_4", "type_5", "type_6"};

class TestGraphDfsVisitor : public BaseGraphDfsVisitorInterface<BaseNode>
{
    public:
        TestGraphDfsVisitor()
            : visitedNodeKeyVector(new std::vector<Key>())
            , visitedNodeVector(new std::vector<BaseNode>())
        {};

        ~TestGraphDfsVisitor()
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
            visitedNodeKeyVector->push_back(nodeKey);
            visitedNodeVector->push_back(node);
        };
        void onFinishNode(const Key& nodeKey, const BaseNode& node) const override {};

    private:
        boost::shared_ptr<std::vector<Key> > visitedNodeKeyVector;
        boost::shared_ptr<std::vector<BaseNode> > visitedNodeVector;
};

class MockBaseBidirectionalGraph : public BaseGraph<BaseNode, BidirectionalGraphType>
{
    public:

        std::map<int, Key> myNodesMap;

        MockBaseBidirectionalGraph()
            : BaseGraph()
        {};

        void createConnection(const Key& fromNodeKey, const Key& toNodeKey)
        {
            std::shared_ptr<Key> from(std::make_shared<Key>(fromNodeKey));
            std::shared_ptr<Key> to(std::make_shared<Key>(toNodeKey));

            BaseGraph<BaseNode, BidirectionalGraphType>::createConnection(from, to);
        }

        void deleteReachableNodesFrom(const Key& node)
        {
            BaseGraph<BaseNode, BidirectionalGraphType>::deleteReachableNodesFrom(std::make_shared<Key>(node));
        }

        void deleteNodeAndAdjacents(const Key& node)
        {
            BaseGraph<BaseNode, BidirectionalGraphType>::deleteNodeAndAdjacents(std::make_shared<Key>(node));
        }

        bool runDfs(const Key& rootNode, const TestGraphDfsVisitor& dfsVisitor)
        {
            return BaseGraph<BaseNode, BidirectionalGraphType>::runDfs(std::make_shared<Key>(rootNode), dfsVisitor);
        }

        void fillGraph()
        {
            // Create Keys that will serve to index Graph nodes
            for(auto node : nodes)
            {
                int nodeId = static_cast<int>(node);
                myNodesMap[nodeId] = (Key(NodeEntityNames[nodeId], NodeTypeNames[nodeId]));
            }

            // ////////////////////////////
            // Graph layout to test:
            // ////////////////////////////
            /*         k1
            //        /  \
            //       k2   k3
            //      /  \  /
            //     k4   k5
            //    /
            //   k6
            // ////////////////////////////*/

            // K1->K2
            createConnection(myNodesMap[K1], myNodesMap[K2]);
            // K1->K3
            createConnection(myNodesMap[K1], myNodesMap[K3]);
            // K2->K4
            createConnection(myNodesMap[K2], myNodesMap[K4]);
            // K2->K5
            createConnection(myNodesMap[K2], myNodesMap[K5]);
            // K4->K6
            createConnection(myNodesMap[K4], myNodesMap[K6]);
            // K3->K5
            createConnection(myNodesMap[K3], myNodesMap[K5]);
        }

        std::map<int, Key> getNodesMapping()
        {
            return myNodesMap;
        }

        std::vector<Key> getReachableNodesFromRoot()
        {
            std::vector<BaseNode> ret;

            TestGraphDfsVisitor vis;
            // Run DFS from root node=K1
            BaseGraph<BaseNode, BidirectionalGraphType>::runDfs(myBiMappingOfNodeDescriptorAndKey.left.at(K1), vis);

            return vis.getVisitedNodesKey();
        }

        std::vector<Key> getAdjacentNodes(const Key& node)
        {
            std::vector<Key> ret;

            std::vector<BaseNode> nodes = BaseGraph<BaseNode, BidirectionalGraphType>::getAdjacentNodes(std::make_shared<Key>
                                          (node));

            for(auto& adjacentNode : nodes)
            {
                ret.push_back(*(adjacentNode.key));
            }

            return ret;
        }

        std::vector<Key> getInNodes(const Key& node)
        {
            std::vector<Key> ret;

            std::vector<BaseNode> nodes = BaseGraph<BaseNode, BidirectionalGraphType>::getInNodes(std::make_shared<Key>(node));

            for(auto& inNode : nodes)
            {
                ret.push_back(*(inNode.key));
            }

            return ret;
        }
};

class BaseGraphTestFixture : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            testBaseGraph_.fillGraph();
            testGraphNodes_ = testBaseGraph_.getNodesMapping();
        }

        MockBaseBidirectionalGraph testBaseGraph_;
        std::map<int, Key> testGraphNodes_;
};

// Validate initial graph setup, including nodes and connections
TEST_F(BaseGraphTestFixture, initialGraphSetup)
{
    // /////////////////////////////////
    // Validate number of nodes
    // /////////////////////////////////

    std::vector<Key> nodesFound = testBaseGraph_.getReachableNodesFromRoot();
    // Visited nodes (from root) shall be equal to number of nodes added to the graph
    ASSERT_EQ(nodesFound.size(), GraphNodes::K_NUMBER) << "Number of Nodes NOT as expected!";

    // /////////////////////////////////
    // Validate node by node
    // /////////////////////////////////

    // check whether each graph node can be found in the visited list
    bool nodesMatches = true;

    for(auto graphNode : testGraphNodes_)
    {
        if(std::find(nodesFound.begin(), nodesFound.end(), graphNode.second) == nodesFound.end())
        {
            // NOT FOUND!
            nodesMatches = false;
            break;
        }
    }

    ASSERT_TRUE(nodesMatches) << "Graph visited nodes does NOT include all nodes from graph!";

    // /////////////////////////////////
    // Validate node connections
    // /////////////////////////////////

    // k1 -> k2
    //    -> k3
    std::vector<Key> k1AdjacentNodes = testBaseGraph_.getAdjacentNodes(testGraphNodes_[K1]);
    ASSERT_EQ(k1AdjacentNodes.size(), 2) << "Number of K1 Adjacent Nodes NOT as expected!";
    ASSERT_TRUE(std::find(k1AdjacentNodes.begin(), k1AdjacentNodes.end(), testGraphNodes_[K2]) != k1AdjacentNodes.end()) <<
            "K1 adjacent nodes does NOT include K2!";
    ASSERT_TRUE(std::find(k1AdjacentNodes.begin(), k1AdjacentNodes.end(), testGraphNodes_[K3]) != k1AdjacentNodes.end()) <<
            "K1 adjacent nodes does NOT include K3!";

    // k2 -> k4
    //    -> k5
    std::vector<Key> k2AdjacentNodes = testBaseGraph_.getAdjacentNodes(testGraphNodes_[K2]);
    ASSERT_EQ(k2AdjacentNodes.size(), 2) << "Number of K2 Adjacent Nodes NOT as expected!";
    ASSERT_TRUE(std::find(k2AdjacentNodes.begin(), k2AdjacentNodes.end(), testGraphNodes_[K4]) != k2AdjacentNodes.end()) <<
            "K2 adjacent nodes does NOT include K4!";
    ASSERT_TRUE(std::find(k2AdjacentNodes.begin(), k2AdjacentNodes.end(), testGraphNodes_[K5]) != k2AdjacentNodes.end()) <<
            "K2 adjacent nodes does NOT include K5!";

    // k3 -> k5
    std::vector<Key> k3AdjacentNodes = testBaseGraph_.getAdjacentNodes(testGraphNodes_[K3]);
    ASSERT_EQ(k3AdjacentNodes.size(), 1) << "Number of K4 Adjacent Nodes NOT as expected!";
    ASSERT_TRUE(std::find(k3AdjacentNodes.begin(), k3AdjacentNodes.end(), testGraphNodes_[K5]) != k3AdjacentNodes.end()) <<
            "K3 adjacent nodes does NOT include K5!";

    // k4 -> k6
    std::vector<Key> k4AdjacentNodes = testBaseGraph_.getAdjacentNodes(testGraphNodes_[K4]);
    ASSERT_EQ(k4AdjacentNodes.size(), 1) << "Number of K4 Adjacent Nodes NOT as expected!";
    ASSERT_TRUE(std::find(k4AdjacentNodes.begin(), k4AdjacentNodes.end(), testGraphNodes_[K6]) != k4AdjacentNodes.end()) <<
            "K4 adjacent nodes does NOT include K6!";

    // k5 -> no adjacent nodes
    std::vector<Key> k5AdjacentNodes = testBaseGraph_.getAdjacentNodes(testGraphNodes_[K5]);
    ASSERT_EQ(k5AdjacentNodes.size(), 0) << "Number of K5 Adjacent Nodes NOT as expected!";

    // k6 -> no adjacent nodes
    std::vector<Key> k6AdjacentNodes = testBaseGraph_.getAdjacentNodes(testGraphNodes_[K6]);
    ASSERT_EQ(k6AdjacentNodes.size(), 0) << "Number of K6 Adjacent Nodes NOT as expected!";

    // /////////////////////////////////
    // Validate the in-nodes of K5
    // /////////////////////////////////

    // k2 -> k5
    // k3 -> k5
    std::vector<Key> k5InNodes = testBaseGraph_.getInNodes(testGraphNodes_[K5]);
    ASSERT_EQ(k5InNodes.size(), 2) << "Number of K5 in-nodes NOT as expected!";
    ASSERT_TRUE(std::find(k5InNodes.begin(), k5InNodes.end(), testGraphNodes_[K2]) != k5InNodes.end()) <<
            "K5 in-nodes does NOT include K2!";
    ASSERT_TRUE(std::find(k5InNodes.begin(), k5InNodes.end(), testGraphNodes_[K3]) != k5InNodes.end()) <<
            "K5 in-nodes does NOT include K3!";
};

// Validate create new node connections
TEST_F(BaseGraphTestFixture, createNodeConnections)
{
    // k6 -> (new) k7
    //    -> (new) k8
    Key k7("key_7", "type_7");
    Key k8("key_8", "type_8");
    testBaseGraph_.createConnection(testGraphNodes_[K6], k7);
    testBaseGraph_.createConnection(testGraphNodes_[K6], k8);

    std::vector<Key> newNodesFound = testBaseGraph_.getReachableNodesFromRoot();
    // Visited nodes (from root) shall be equal to number of nodes added to the graph
    ASSERT_EQ(newNodesFound.size(), GraphNodes::K_NUMBER + 2) << "Number of Nodes NOT as expected!";

    std::vector<Key> new6AdjacentNodes = testBaseGraph_.getAdjacentNodes(testGraphNodes_[K6]);
    ASSERT_EQ(new6AdjacentNodes.size(), 2) << "Number of K6 Adjacent Nodes NOT as expected!";
    ASSERT_TRUE(std::find(new6AdjacentNodes.begin(), new6AdjacentNodes.end(), k7) != new6AdjacentNodes.end()) <<
            "K6 adjacent nodes does NOT include K7!";
    ASSERT_TRUE(std::find(new6AdjacentNodes.begin(), new6AdjacentNodes.end(), k8) != new6AdjacentNodes.end()) <<
            "K6 adjacent nodes does NOT include K8!";
};

// Validate delete reachable nodes
TEST_F(BaseGraphTestFixture, deleteReachableNodes)
{
    // (delete) k2 -> (delete) ... (reachable nodes are deleted)
    testBaseGraph_.deleteReachableNodesFrom(testGraphNodes_[K2]);

    // //////////////////////////////
    // Graph layout after delete k2
    // //////////////////////////////
    /*          k1
    //        /    \
    //       k2(x)  k3
    //      /    \
    //     k4(x)  k5(x)
    //    /
    //   k6(x)
    // ////////////////////////////*/

    std::vector<Key> newNodesFound = testBaseGraph_.getReachableNodesFromRoot();
    // Visited nodes (from root) shall be equal to number of nodes added to the graph
    ASSERT_EQ(newNodesFound.size(), 2) << "Number of Nodes NOT as expected!";

    // Next connection must remain
    // k1 -> k3
    std::vector<Key> k1AdjacentNodes = testBaseGraph_.getAdjacentNodes(testGraphNodes_[K1]);
    ASSERT_EQ(k1AdjacentNodes.size(), 1) << "Number of K1 Adjacent Nodes NOT as expected!";
    ASSERT_TRUE(std::find(k1AdjacentNodes.begin(), k1AdjacentNodes.end(), testGraphNodes_[K3]) != k1AdjacentNodes.end())
            << "K3 adjacent nodes does NOT include K3!";
}

// Validate delete adjacent nodes
TEST_F(BaseGraphTestFixture, deleteNodeAndAdjacentNodes)
{
    // (delete) k4 -> (delete) ... ( node and reachable nodes are deleted)
    testBaseGraph_.deleteNodeAndAdjacents(testGraphNodes_[K4]);

    // //////////////////////////////
    // Graph layout after delete k4
    // //////////////////////////////
    /*          k1
    //        /    \
    //       k2     k3
    //      /   \
    //     k4(x) k5
    //    /
    //   k6(x)
    // ////////////////////////////*/

    std::vector<Key> newNodesFound = testBaseGraph_.getReachableNodesFromRoot();
    // Visited nodes (from root) shall be equal to number of nodes added to the graph
    ASSERT_EQ(newNodesFound.size(), 4) << "Number of Nodes NOT as expected!";

    // K2 MUST HAVE only K5 adjacent node
    std::vector<Key> k4AdjacentNodes = testBaseGraph_.getAdjacentNodes(testGraphNodes_[K2]);
    ASSERT_EQ(k4AdjacentNodes.size(), 1) << "Number of K2 Adjacent Nodes NOT as expected!";
}

// Validate DFS algorithm
TEST_F(BaseGraphTestFixture, runDfsAlgorithm)
{
    // /////////////////////////////
    // Run DFS from root node=K1
    // /////////////////////////////
    TestGraphDfsVisitor vis;
    testBaseGraph_.runDfs(testGraphNodes_[K1], vis);
    std::vector<Key> nodesFound = vis.getVisitedNodesKey();

    // /////////////////////////////////
    // Validate visited nodes from K1
    // /////////////////////////////////

    // Visited nodes (from root) shall be equal to number of nodes added to the graph
    ASSERT_EQ(nodesFound.size(), GraphNodes::K_NUMBER) << "Number of Nodes NOT as expected!";
    // check whether each graph node can be found in the visited list
    bool nodesMatches = true;

    for(auto graphNode : testGraphNodes_)
    {
        if(std::find(nodesFound.begin(), nodesFound.end(), graphNode.second) == nodesFound.end())
        {
            // NOT FOUND!
            nodesMatches = false;
            break;
        }
    }

    ASSERT_TRUE(nodesMatches) << "Graph visited nodes does NOT include all nodes from graph!";

    // /////////////////////////////////////////////////////////////

    // /////////////////////////////
    // Run DFS from root node=K2
    // /////////////////////////////

    testBaseGraph_.runDfs(testGraphNodes_[K2], vis);
    nodesFound = vis.getVisitedNodesKey();

    // /////////////////////////////////
    // Validate visited nodes from K2
    // /////////////////////////////////

    // Visited nodes shall be equal to number of nodes added to the graph
    ASSERT_EQ(nodesFound.size(), 4) << "Number of Nodes NOT as expected!";
    // check whether each node reachable from K2 (K2-inclusive,K4,K5,K6) can be found in the visited list
    EXPECT_TRUE(std::find(nodesFound.begin(), nodesFound.end(), testGraphNodes_[K2]) != nodesFound.end());
    EXPECT_TRUE(std::find(nodesFound.begin(), nodesFound.end(), testGraphNodes_[K4]) != nodesFound.end());
    EXPECT_TRUE(std::find(nodesFound.begin(), nodesFound.end(), testGraphNodes_[K5]) != nodesFound.end());
    EXPECT_TRUE(std::find(nodesFound.begin(), nodesFound.end(), testGraphNodes_[K6]) != nodesFound.end());

    // Now delete K5, that was reachable node from K2
    testBaseGraph_.deleteReachableNodesFrom(testGraphNodes_[K5]);

    // /////////////////////////////
    // AFTER delete K5,
    // Run DFS from root node=K2
    // /////////////////////////////

    testBaseGraph_.runDfs(testGraphNodes_[K2], vis);
    nodesFound = vis.getVisitedNodesKey();

    // /////////////////////////////////
    // Validate visited nodes from K2
    // /////////////////////////////////

    // Visited nodes shall be equal to number of nodes added to the graph
    ASSERT_EQ(nodesFound.size(), 3) << "Number of Nodes NOT as expected!";
    // check whether each node reachable from K2 (K2-inclusive,K4,K6) can be found in the visited list
    EXPECT_TRUE(std::find(nodesFound.begin(), nodesFound.end(), testGraphNodes_[K2]) != nodesFound.end());
    EXPECT_TRUE(std::find(nodesFound.begin(), nodesFound.end(), testGraphNodes_[K4]) != nodesFound.end());
    EXPECT_TRUE(std::find(nodesFound.begin(), nodesFound.end(), testGraphNodes_[K6]) != nodesFound.end());
}

