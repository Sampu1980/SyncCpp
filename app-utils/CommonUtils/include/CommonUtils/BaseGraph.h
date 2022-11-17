#ifndef BASEGRAPH_H
#define BASEGRAPH_H

#include <type_traits>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <functional>
#include <boost/config.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/breadth_first_search.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/bimap.hpp>

#include "CommonUtils/Key.h"
#include "CommonUtils/RecursiveSharedMutex.h"

// Choose the type of the Base Graph between:
// Directed:       set of vertices connected by directed edges
using DirectedGraphType = boost::directedS;
// Bidirectional:  directed with access to both the in-edges and out-edges (which we call bidirectional)
using BidirectionalGraphType = boost::bidirectionalS;

/**
 * @brief Define the possible colors to render a node in graphviz format.
 * The graphviz format allows to render nodes using different color set (e.g. to distinguish the node state).
 * To achieve this one can set the color property of a BaseNode object.
 *
 * Sample output (using BaseGraphUtils::renderToGraphviz):
 *
   digraph G {
   graph [bgcolor=lightgrey]
   edge [color=red]
   0 [label="ADMINDOWN"][color=grey];
   1 [label="LOS"][color=red];
   2 [label="LOF"][color=yellow];
   3 [label="LOM"][color=grey];
   4 [label="AIS"][color=grey];
   5 [label="OOM"][color=grey];
   6 [label="TIM"][color=grey];
   0->3  [color=black]
   ;
   1->2  [color=black]
   ;
   3->4  [color=black]
   ;
   5->6  [color=black]
   ;
   }
 */
enum class NodeColor
{
    RED = 0,  ///< RED
    YELLOW,   ///< YELLOW
    GREY,     ///< GREY
    BLACK,    ///< BLACK
    BLUE,     ///< BLUE
    GREEN,    ///< GREEN
    NCOLORS   ///< NCOLORS
};

/**
 * @brief Defines the base node that will represent the vertices of the BaseGraph (BGL implementation)
 */
struct BaseNode
{
    std::shared_ptr<Key> key; ///< Key that will uniquely identify a node in the graph

    // Rendable properties (graphviz format)
    // Make it mutable to be able to render the graph using boost graphviz
    // (see BaseGraphUtils)
    mutable std::string label; ///< the node label that will be rendered to graphviz format
    mutable std::string color; ///< the node color that will be rendered to graphviz format
    mutable bool deleted;      ///< the deleted state of the node

    explicit BaseNode(); ///< Default constructor

    /**
     * @brief Constructor
     * @param k node key
     */
    BaseNode(std::shared_ptr<Key> k);

    /**
     * @brief Constructor
     * @param k node key
     * @param name name of the node to be used as label
     * @param c node color
     * @see NodeColor
     */
    BaseNode(std::shared_ptr<Key> k, const std::string& name, const NodeColor& c);

    /**
     * @brief Copy constructor
     * @param node to copy from
     */
    BaseNode(const BaseNode& node);

    /**
     * @brief Default Destructor
     */
    virtual ~BaseNode() = default;

    /**
     * @brief Set node label name
     * @param pLabel label
     * @return reference to (modified) this object
     */
    const BaseNode& setLabel(const std::string& pLabel);

    /**
     * @brief Set node label name
     * @param pColor color
     * @return reference to (modified) this object
     */
    const BaseNode& setColor(NodeColor pColor) const;


    bool operator==(const BaseNode& rhs) const
    {
        return (((key && rhs.key && *key == *(rhs.key)) || (!key && !rhs.key)) &&
                label == rhs.label &&
                color == rhs.color &&
                deleted == rhs.deleted);
    }

    bool operator!=(const BaseNode& rhs) const
    {
        return ! operator==(rhs);
    }

    // /////////////////////
    // Cast Implementations
    // /////////////////////

    /**
     * @brief Explicit call to cast to template T type
     * @return base node reference casted to T type
     */
    template<typename T>
    T castTo() const
    {
        return dynamic_cast<T>(*this);
    };

    /**
     * @brief Operator() to conversion to pointer to any type
     * @return base node pointer casted to T type
     */
    template<typename T>
    operator T* ()
    {
        return dynamic_cast<T*>(this);
    }

    /**
     * @brief Operator() to conversion to reference to any type
     * @return base node reference casted to T type
     */
    template<typename T>
    operator T& ()
    {
        return dynamic_cast<T&>(*this);
    }

    /**
     * @brief Operator() to conversion to reference to any type
     * @return base node reference casted to T type
     */
    template<typename T>
    operator T& () const
    {
        return dynamic_cast<T&>(*this);
    }

    /**
     * @brief Operator() to conversion to reference to any const type
     * @return base node reference casted to const T type
     */
    template<typename T>
    operator const T& () const
    {
        return dynamic_cast<const T&>(*this);
    }
};

/**
 * @brief Interface that abstracts what actions are taken at each event-point within the DFS algorithm.
 * When running the DFS algorithm, a number of connected nodes will be visited and on each visit, next callback methods will be executed.
 *
 * @see BaseGraph::runDfs
 *
 * @note User can extend BaseNode capabilities by having its own Node implementation.
 *       to guarantee consistency, this is a template method that defines as template parameter: the NodeType.
 *       The NoteType MUST be base of BaseNode, otherwise compilation error will be given.
 *       To achieve this the following metafunction 'std::enable_if_t' is used, along side with 'std::is_base_of',
 *       to perform this check at compile time.
 */
template<class NodeType, typename V = std::enable_if_t<std::is_base_of<BaseNode, NodeType>::value, void>>
class BaseGraphDfsVisitorInterface
{
    public:
        /**
         * @brief Callback executed when first node is visited by DFS algorithm
         * @param nodeKey key associated to node
         * @param node object that represents the node
         *
         * @see Key
         * @see BaseNode
         */
        virtual void onStartNode(const Key& nodeKey, const NodeType& node) const = 0;

        /**
         * @brief Callback executed for every node that is discovered by DFS algorithm
         * @param startNode indicate whether visited node is the start node
         * @param nodeKey key associated to node
         * @param node object that represents the node
         *
         * @see Key
         * @see BaseNode
         */
        virtual void onDiscoverNode(const bool& startNode, const Key& nodeKey, const NodeType& node) const = 0;

        /**
         * @brief Callback executed for every connection which points from a node to one of its ancestors
         * @param sourceNodeKey key associated to node
         * @param sourceNode object that represents the node
         * @param targetNodeKey key associated to node
         * @param targetNode object that represents the node
         *
         * @see Key
         * @see BaseNode
         */
        virtual void onBackConnection(const Key& sourceNodeKey, const NodeType& sourceNode,
                                      const Key& targetNodeKey, const NodeType& targetNode) const {};

        /**
         * @brief Callback executed when last node is visited by DFS algorithm
         * @param nodeKey key associated to node
         * @param node object that represents the node
         *
         * @see Key
         * @see BaseNode
         */
        virtual void onFinishNode(const Key& nodeKey, const NodeType& node) const = 0;

        /**
         * @brief Default Destructor
         */
        virtual ~BaseGraphDfsVisitorInterface() = default;
};

/**
 * @brief Interface that abstracts what actions are taken at each event-point within the BFS algorithm.
 * When running the BFS algorithm, a number of connected nodes will be visited and on each visit, next callback methods will be executed.
 *
 * @see BaseGraph::runBfs
 *
 * @note User can extend BaseNode capabilities by having its own Node implementation.
 *       to guarantee consistency, this is a template method that defines as template parameter: the NodeType.
 *       The NoteType MUST be base of BaseNode, otherwise compilation error will be given.
 *       To achieve this the following metafunction 'std::enable_if_t' is used, along side with 'std::is_base_of',
 *       to perform this check at compile time.
 */
template<class NodeType, typename V = std::enable_if_t<std::is_base_of<BaseNode, NodeType>::value, void>>
class BaseGraphBfsVisitorInterface
{
    public:
        /**
         * @brief Callback executed when first node is visited by BFS algorithm
         * @param nodeKey key associated to node
         * @param node object that represents the node
         *
         * @see Key
         * @see BaseNode
         */
        virtual void onStartNode(const Key& nodeKey, const NodeType& node) const = 0;

        /**
         * @brief Callback executed for every node that is discovered by BFS algorithm
         * @param startNode indicate whether visited node is the start node
         * @param nodeKey key associated to node
         * @param node object that represents the node
         *
         * @see Key
         * @see BaseNode
         */
        virtual void onDiscoverNode(const bool& startNode, const Key& nodeKey, const NodeType& node) const = 0;

        /**
         * @brief Callback executed when last node is visited by BFS algorithm
         * @param nodeKey key associated to node
         * @param node object that represents the node
         *
         * @see Key
         * @see BaseNode
         */
        virtual void onFinishNode(const Key& nodeKey, const NodeType& node) const = 0;

        /**
         * @brief Callback executed when search ends
         * @param nodeKey key associated to node
         * @param node object that represents the node
         *
         * @see Key
         * @see BaseNode
         */
        virtual void onEndSearch(const Key& nodeKey, const NodeType& node) const = 0;

        /**
         * @brief Default Destructor
         */
        virtual ~BaseGraphBfsVisitorInterface() = default;
};

/**
 * @class BaseGraph
 * @brief This class provides an implementation of a directed or bidirectional graph (based BGL).
 * Next operations are allowed:
 * -> Create connection from Node A to Node B;
 * -> Delete given node and the reachable ones;
 * -> Run DFS algorithm starting from a giving node.
 * -> Run BFS algorithm starting from a giving node.
 *    Both algorithms will perform a search on the graph starting on a given start node and visiting all reachable nodes.
 *    It is possible to instruct the algorithm implementation to execute callback when a node or a edge is visited.
 *    To achieve this one must implement, depending the selected algorithm:
 *    -> BaseGraphDfsVisitorInterface class and pass object as argument to runDfs method.
 *    -> BaseGraphBfsVisitorInterface class and pass object as argument to runBfs method.
 *
 * @note Hereafter 'node' and 'connection' will be used in opposite to what Boost defines.
 *       So for clarifications reasons the follow means:
 *       -> node is a 'vertex' in boost nomenclature
 *       -> connection is a 'edge' in boost nomenclature
 *
 * @note User can extent BaseNode capabilities by having its own Node implementation.
 *       to guarantee consistency, this is a template method that defines as template parameter: the NodeType.
 *       The NoteType MUST be base of BaseNode, otherwise compilation error will be given.
 *       To achieve this the following metafunction 'std::enable_if_t' is used, along side with 'std::is_base_of',
 *       to perform this check at compile time.
 */
template<class NodeType = BaseNode,
         class GraphType = DirectedGraphType,
         typename V = std::enable_if_t<std::is_base_of<BaseNode, NodeType>::value, void>>
class BaseGraph
{
    public:
        /**
         * @brief Function handler to be used along with createConnection and to be executed
         *        right after a node is connected to other.
         * @param fromNode start-point node of the connection
         * @param toNode end-point node of the connection
         */
        typedef std::function<void (NodeType& fromNode, NodeType& toNode)> PosConnectedActionFunctionType;

        /**
         * @brief Function handler to be used along with deleteNodeAndAdjacents and to be executed
         *        before the deletion of the adjacent node of the given node
         * @param node node in the graph to be deleted, along with and its adjacent nodes
         */
        typedef std::function<void (NodeType& node)> DeleteActionFunctionType;

        /**
         * @brief Default Constructor
         */
        BaseGraph() = default;

        /**
         * @brief Default Destructor
         */
        ~BaseGraph() = default;

        /**
         * @brief Create a directed connection between two nodes in the graph: from given fromNode to toNode.
         *        The nodes will be created in the graph if not exists.
         * @param fromNodeKey the source point of the connection
         * @param toNodeKey the destiny point of the connection
         * @param fromNodeColor default color
         * @param toNodeColor default color
         * @return true indicates connection was created; false otherwise (e.g. already created)
         */
        bool createConnection(std::shared_ptr<Key> fromNodeKey, std::shared_ptr<Key> toNodeKey,
                              const NodeColor fromNodeColor = NodeColor::BLACK,
                              const NodeColor& toNodeColor = NodeColor::BLACK);

        /**
         * @brief Create a directed connection between two nodes in the graph: from given fromNode to toNode.
         *        The nodes will be created in the graph if not exists.
         * @param fromNodeKey the source point of the connection
         * @param toNodeKey the destiny point of the connection
         * @param posConnectedActionFunction function to be executed right after connection is made.
         *      The function MUST define two reference parameters to node:
         *      - fromNodeKey: the start side of the connection
         *      - toNodeKey:   the end side of the connection
         *      e.g. One can define a function to modify the properties of the nodes (see example in SuppressionEngine)
         * @return true indicates connection was created; false otherwise (e.g. already created)
         */
        bool createConnection(std::shared_ptr<Key> fromNodeKey, std::shared_ptr<Key> toNodeKey,
                              PosConnectedActionFunctionType posConnectedActionFunction);

        /**
         * @brief Delete given node and all reachable from it
         * @param node key that represents the node to be deleted
         */
        void deleteReachableNodesFrom(std::shared_ptr<Key> node);

        /**
         * @brief Delete the given key node and its adjacent nodes
         * @param node node key
         */
        void deleteNodeAndAdjacents(std::shared_ptr<Key> node);

        /**
         * @brief Delete the given key node and its adjacent nodes
         * The given function is executed for each adjacent node and right before its deletion
         * @param node node key
         * @param preDeleteActionfunction function to be executed right before the deletion of the node
         */
        void deleteNodeAndAdjacents(std::shared_ptr<Key> node,
                                    DeleteActionFunctionType preDeleteActionfunction);

        /**
         * @brief Delete the given key node
         * @param node node key
         */
        void deleteNode(std::shared_ptr<Key> node);

        /**
         * @brief Get a container (vector) with the list of adjacent nodes from a given node key
         * For example, taking the graph {A->B, A->C}, then B and C will be the adjacent nodes of A.
         * @param node node key
         * @return vector of adjacent nodes
         */
        std::vector<NodeType> getAdjacentNodes(std::shared_ptr<Key> node) const;

        /**
         * @brief Get a container (vector) with the list of the adjacent node keys from a given node key
         * For example, taking the graph {A->B, A->C}, then B and C will be the adjacent nodes of A.
         * @param node node key
         * @return vector of adjacent node key pointers
         */
        std::vector<std::shared_ptr<Key>> getAdjacentNodesKeys(std::shared_ptr<Key> node) const;

        /**
         * @brief Get a container (vector) with the list of nodes are connecting (in-nodes)
         *         to the given node key
         * For example, taking the graph {A->C, B->C}, then A and B will be the in-nodes of C.
         * @NOTE: This function will only be available to work if graph is of type Bidirectional!
         *        Otherwise, the DirectedGraphType, an empty list will always be returned
         * @param node node key
         * @return vector of in-nodes
         */
        std::vector<NodeType> getInNodes(std::shared_ptr<Key> node) const;

        /**
         * @brief Get a container (vector) with the list of node keys are connecting (in-nodes)
         *         to the given node key
         * For example, taking the graph {A->C, B->C}, then A and B will be the in-nodes of C.
         * @NOTE: This function will only be available to work if graph is of type Bidirectional!
         *        Otherwise, the DirectedGraphType, an empty list will always be returned
         * @param node node key
         * @return vector of in-nodes key pointers
         */
        std::vector<std::shared_ptr<Key>> getInNodesKeys(std::shared_ptr<Key> node) const;

        /**
         * @brief Get the node represented by given node key
         * @param nodeKey node key
         * @return pair where
         * - first indicates whether node was found, or not
         * - second is the node found
         */
        std::pair<bool, NodeType> getNode(std::shared_ptr<Key> nodeKey) const;

        /**
         * @brief Get the reference to the node represented by given node key
         * @param nodeKey node key
         * @return pair where
         * - first indicates whether node was found, or not
         * - second is the node found
         */
        std::pair<bool, NodeType&> nodeAt(std::shared_ptr<Key> nodeKey) const;

        /**
         * @brief Execute the DFS (Depth-First-Search) algorithm over the graph.
         * @param rootNode starting point for DFS
         * @param dfsVisitor determines what actions are taken at each event-point within the algorithm
         * @return true if rootNode was found and DFS algorithm has been executed; false otherwise
         */
        bool runDfs(std::shared_ptr<Key> rootNode, const BaseGraphDfsVisitorInterface<NodeType>& dfsVisitor);

        /**
         * @brief Execute the DFS (Depth-First-Search) algorithm over the graph.
         * @param rootNode starting point for DFS
         * @param dfsVisitor determines what actions are taken at each event-point within the algorithm
         * @param lockExclusiveMode indicate whether to run DFS algorithm in exclusive lock mode, or not (shared mode)
         * @return true if rootNode was found and DFS algorithm has been executed; false otherwise
         */
        bool runDfs(std::shared_ptr<Key> rootNode, const BaseGraphDfsVisitorInterface<NodeType>& dfsVisitor,
                    bool lockExclusiveMode);

        /**
         * @brief Execute the BFS (Breadth-First-Search) algorithm over the graph.
         * @param rootNode starting point for BFS
         * @param bfsVisitor determines what actions are taken at each event-point within the algorithm
         * @return true if rootNode was found and BFS algorithm has been executed; false otherwise
         */
        bool runBfs(std::shared_ptr<Key> rootNode, const BaseGraphBfsVisitorInterface<NodeType>& bfsVisitor);

        /**
         * @brief Execute the BFS (Breadth-First-Search) algorithm over the graph.
         * @param rootNode starting point for BFS
         * @param bfsVisitor determines what actions are taken at each event-point within the algorithm
         * @param lockExclusiveMode indicate whether to run BFS algorithm in exclusive lock mode, or not (shared mode)
         * @return true if rootNode was found and BFS algorithm has been executed; false otherwise
         */
        bool runBfs(std::shared_ptr<Key> rootNode, const BaseGraphBfsVisitorInterface<NodeType>& bfsVisitor,
                    bool lockExclusiveMode);

        /**
         * @brief Write a BGL into an output stream in graphviz 'dot' format.
         * @param out stream
         */
        void renderToGraphviz(std::ostream& out) const;

    protected:
        // /////////////////////////////////////////
        // Configure a Graph (BOOST)
        // /////////////////////////////////////////
        typedef boost::adjacency_list<boost::listS, boost::vecS, GraphType, NodeType, boost::no_property> InternalGraph;
        typedef typename boost::graph_traits<InternalGraph>::vertex_descriptor InternalNodeDescriptor;
        typedef typename boost::graph_traits<InternalGraph>::edge_descriptor InternalEdgeDescriptor;

        // /////////////////////////////////////////
        // DFS visitor representations
        // /////////////////////////////////////////

        class GraphDfsGenericVisitor : public boost::default_dfs_visitor
        {
            public:
                GraphDfsGenericVisitor(const BaseGraphDfsVisitorInterface<NodeType>& visitor, const BaseGraph& graphRef);
                ~GraphDfsGenericVisitor() = default;
                // implementation of boost::default_dfs_visitor
                void start_vertex(int s, const InternalGraph& g) const;
                void discover_vertex(int v, const InternalGraph& g) const;
                void back_edge(InternalEdgeDescriptor e, const InternalGraph& g) const;
                void finish_vertex(int u, const InternalGraph& g) const;
            private:
                const BaseGraphDfsVisitorInterface<NodeType>& customDfsVisitor;
                const BaseGraph& baseGraph;
                mutable bool startNode;
        };

        // /////////////////////////////////////////
        // BFS visitor representations
        // /////////////////////////////////////////

        class GraphBfsGenericVisitor : public boost::default_bfs_visitor
        {
            public:
                GraphBfsGenericVisitor(const BaseGraphBfsVisitorInterface<NodeType>& visitor, const BaseGraph& graphRef);
                ~GraphBfsGenericVisitor() = default;
                // implementation of boost::default_bfs_visitor
                void discover_vertex(int v, const InternalGraph& g) const;
                void finish_vertex(int u, const InternalGraph& g) const;
            private:
                const BaseGraphBfsVisitorInterface<NodeType>& customBfsVisitor;
                const BaseGraph& baseGraph;
                mutable bool startNode;
                mutable int numberOfDiscovered;
                mutable int numberOfFinished;
        };

        // /////////////////////////////////////////
        // Internal DFS visitor for delete operation
        // /////////////////////////////////////////

        class GraphDfsDeleteVisitor : public boost::default_dfs_visitor
        {
            public:
                GraphDfsDeleteVisitor();
                ~GraphDfsDeleteVisitor() = default;
                // implementation of boost::default_dfs_visitor
                void discover_vertex(int v, const InternalGraph& g) const;
        };

        // //////////////////////////////////////
        // Class Members
        // //////////////////////////////////////
        /**
         * @brief Internal function to add a node in the graph
         * @param nodeKey key that represents the node
         * @param node node object
         * @return internal node descriptor
         */
        InternalNodeDescriptor addNodeToGraph(std::shared_ptr<Key> nodeKey, const NodeType& node);

        /**
         * @brief Internal function that create a connection (edge in boost nomenclature) in the graph between two nodes:
         *        from given fromNode to toNode
         * @param fromNodeKey the source node key
         * @param fromNode the source node
         * @param toNodeKey the destiny node key
         * @param toNode the destiny node
         * @return true if connection was added sucessfully in the graph (not already exists); false otherwise
         */
        bool addConnectionToGraph(std::shared_ptr<Key> fromNodeKey, const NodeType& fromNode, std::shared_ptr<Key> toNodeKey,
                                  const NodeType& toNode);

        /**
         * @brief Internal function that will delete all nodes (BaseNode), from the graph, that are marked as deleted.
         *        (BaseNode::deleted flag is set).
         * @see BaseNode
         */
        void deleteNodesMarkedAsTobeDeleted();

        /**
         * @brief Execute the DFS (Depth-First-Search) algorithm over the graph.
         * @param rootNode starting point for DFS
         * @param dfsVisitor determines what actions are taken at each event-point within the algorithm
         * @return true if rootNode was found and DFS algorithm has been executed; false otherwise
         */
        template< template<typename MT> class MutexLockType>
        bool internalRunDfs(std::shared_ptr<Key> rootNode, const BaseGraphDfsVisitorInterface<NodeType>& dfsVisitor);

        /**
         * @brief Execute the BFS (Breadth-First-Search) algorithm over the graph.
         * @param rootNode starting point for BFS
         * @param bfsVisitor determines what actions are taken at each event-point within the algorithm
         * @return true if rootNode was found and BFS algorithm has been executed; false otherwise
         */
        template< template<typename MT> class MutexLockType>
        bool internalRunBfs(std::shared_ptr<Key> rootNode, const BaseGraphBfsVisitorInterface<NodeType>& bfsVisitor);

        std::vector<NodeType> getInNodesInternal(std::shared_ptr<Key> node, DirectedGraphType type) const;
        std::vector<NodeType> getInNodesInternal(std::shared_ptr<Key> node, BidirectionalGraphType type) const;

        std::vector<std::shared_ptr<Key>> getInNodesKeysInternal(std::shared_ptr<Key> node, DirectedGraphType type) const;
        std::vector<std::shared_ptr<Key>> getInNodesKeysInternal(std::shared_ptr<Key> node, BidirectionalGraphType type) const;

        // Rational: 'mutable'
        // Make it mutable to be able to render the graph using graphviz
        //(https://stackoverflow.com/questions/34160290/boostgraph-compilation-issue-with-dynamic-properties-and-write-graphviz)
        mutable InternalGraph myGraph; ///< boost graph object

        typedef boost::bimaps::bimap<InternalNodeDescriptor, boost::bimaps::unordered_set_of<std::shared_ptr<Key>, PolymorphicKeyHasher>>
                NodeDescriptorKeyBimapType;
        typedef typename NodeDescriptorKeyBimapType::value_type NodeKeyMappingType;
        NodeDescriptorKeyBimapType myBiMappingOfNodeDescriptorAndKey; ///< Internal bi-mapping between Node descriptor<=>Key

        /**
         * @brief Mutex to protect handling of the Graph (add/delete nodes and run DFS/BFS algorithms)
         */
        mutable RecursiveSharedMutex myMutex;
};

#include "BaseGraph.hpp" // Template implementation

#endif // BASEGRAPH_H

