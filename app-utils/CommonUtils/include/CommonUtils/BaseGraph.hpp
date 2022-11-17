// ///////////////////////////////////
// BaseGraph Template implementation
// ///////////////////////////////////

// ///////////////////////////////
// BaseGraph implementation
// ///////////////////////////////
template<class NodeType, class GraphType, typename V>
bool BaseGraph<NodeType, GraphType, V>::createConnection(std::shared_ptr<Key> fromNodeKey,
                                                         std::shared_ptr<Key> toNodeKey,
                                                         const NodeColor fromNodeColor, const NodeColor& toNodeColor)
{
    return addConnectionToGraph(fromNodeKey,
                                NodeType{fromNodeKey}.setLabel(fromNodeKey->getShortDescription()).setColor(fromNodeColor),
                                toNodeKey,
                                NodeType{toNodeKey}.setLabel(toNodeKey->getShortDescription()).setColor(toNodeColor));
}

template<class NodeType, class GraphType, typename V>
bool BaseGraph<NodeType, GraphType, V>::createConnection(std::shared_ptr<Key> fromNodeKey,
                                                         std::shared_ptr<Key> toNodeKey,
                                                         BaseGraph<NodeType, GraphType, V>::PosConnectedActionFunctionType
                                                         posConnectedActionFunction)
{
    bool status = addConnectionToGraph(fromNodeKey, NodeType{fromNodeKey}.setLabel(fromNodeKey->getShortDescription()),
                                       toNodeKey, NodeType{toNodeKey}.setLabel(toNodeKey->getShortDescription()));

    // Validate whether node connection was made
    if(status && posConnectedActionFunction)
    {
        // Now execute given function handler after connection created, passing the nodes into
        posConnectedActionFunction(myGraph[myBiMappingOfNodeDescriptorAndKey.right.at(fromNodeKey)],
                                   myGraph[myBiMappingOfNodeDescriptorAndKey.right.at(toNodeKey)]);
    }

    return status;
}

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::deleteReachableNodesFrom(std::shared_ptr<Key> node)
{
    // Removing node and connections needs exclusive access to graph
    std::lock_guard<RecursiveSharedMutex> lock(myMutex);

    auto searchNode = myBiMappingOfNodeDescriptorAndKey.right.find(node);

    if(searchNode != myBiMappingOfNodeDescriptorAndKey.right.end())
    {
        GraphDfsDeleteVisitor deleteVisitor;
        // Visit all nodes that are reachable from given node (inclusive) => this will mark the nodes as to be 'deleted'
        boost::depth_first_visit(myGraph,
                                 myBiMappingOfNodeDescriptorAndKey.right.at(node), // the start node
                                 deleteVisitor,
                                 boost::make_vector_property_map<boost::default_color_type>(boost::get(boost::vertex_index,
                                         myGraph)));
        deleteNodesMarkedAsTobeDeleted();
    }
}

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::deleteNodeAndAdjacents(std::shared_ptr<Key> node)
{
    deleteNodeAndAdjacents(node, DeleteActionFunctionType());
}

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::deleteNodeAndAdjacents(std::shared_ptr<Key> node,
                                                               BaseGraph<NodeType, GraphType, V>::DeleteActionFunctionType preDeleteActionfunction)
{
    // Removing node and connections needs exclusive access to graph
    std::lock_guard<RecursiveSharedMutex> lock(myMutex);

    auto searchNode = myBiMappingOfNodeDescriptorAndKey.right.find(node);

    if(searchNode != myBiMappingOfNodeDescriptorAndKey.right.end())
    {
        typename InternalGraph::adjacency_iterator adjacentIt;
        typename InternalGraph::adjacency_iterator adjacentEnd;
        // boost::adjacent_vertices gives a std::pair<adjacency_iterator, adjacency_iterator>. Tie those to iterators
        boost::tie(adjacentIt, adjacentEnd) = boost::adjacent_vertices(myBiMappingOfNodeDescriptorAndKey.right.at(node),
                                                                       myGraph);

        // Mark the node and its adjacents as to be 'deleted'
        myGraph[myBiMappingOfNodeDescriptorAndKey.right.at(node)].deleted = true;

        for(; adjacentIt != adjacentEnd; ++adjacentIt)
        {
            // Now execute given function handler, if not empty
            if(preDeleteActionfunction)
            {
                preDeleteActionfunction(myGraph[*adjacentIt]);
            }

            myGraph[*adjacentIt].deleted = true;
        }

        deleteNodesMarkedAsTobeDeleted();
    }
}

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::deleteNode(std::shared_ptr<Key> node)
{
    // Removing node and connections need exclusive access to graph
    std::lock_guard<RecursiveSharedMutex> lock(myMutex);

    auto searchNode = myBiMappingOfNodeDescriptorAndKey.right.find(node);

    if(searchNode != myBiMappingOfNodeDescriptorAndKey.right.end())
    {
        // Mark the node to be 'deleted'
        myGraph[myBiMappingOfNodeDescriptorAndKey.right.at(node)].deleted = true;

        deleteNodesMarkedAsTobeDeleted();
    }
}

template<class NodeType, class GraphType, typename V>
std::vector<NodeType> BaseGraph<NodeType, GraphType, V>::getAdjacentNodes(std::shared_ptr<Key> node) const
{
    std::vector<NodeType> ret;

    auto searchNode = myBiMappingOfNodeDescriptorAndKey.right.find(node);

    if(searchNode != myBiMappingOfNodeDescriptorAndKey.right.end())
    {
        typename InternalGraph::adjacency_iterator neighbourIt;
        typename InternalGraph::adjacency_iterator neighbourEnd;
        // boost::adjacent_vertices gives a std::pair<adjacency_iterator, adjacency_iterator>. Tie those to iterators
        boost::tie(neighbourIt, neighbourEnd) =
            boost::adjacent_vertices(myBiMappingOfNodeDescriptorAndKey.right.at(node), myGraph);

        for(; neighbourIt != neighbourEnd; ++neighbourIt)
        {
            ret.push_back(myGraph[*neighbourIt]); // dereference neighbourIt, get the vertice_descriptor
        }
    }

    return ret;
}

template<class NodeType, class GraphType, typename V>
std::vector<std::shared_ptr<Key>> BaseGraph<NodeType, GraphType, V>::getAdjacentNodesKeys(
                                   std::shared_ptr<Key> node) const
{
    std::vector<std::shared_ptr<Key>> ret;

    typename InternalGraph::adjacency_iterator neighbourIt;
    typename InternalGraph::adjacency_iterator neighbourEnd;
    // boost::adjacent_vertices gives a std::pair<adjacency_iterator, adjacency_iterator>. Tie those to our iterators
    boost::tie(neighbourIt, neighbourEnd) =
        boost::adjacent_vertices(myBiMappingOfNodeDescriptorAndKey.right.at(node), myGraph);

    for(; neighbourIt != neighbourEnd; ++neighbourIt)
    {
        ret.push_back(myBiMappingOfNodeDescriptorAndKey.left.at(*neighbourIt));
    }

    return ret;
}

template<class NodeType, class GraphType, typename V>
std::vector<NodeType> BaseGraph<NodeType, GraphType, V>::getInNodes(std::shared_ptr<Key> node) const
{
    // Call the overloaded internal function that, depending on the graph type the implementation is supported or not
    return getInNodesInternal(node, GraphType{});
}

template<class NodeType, class GraphType, typename V>
std::vector<NodeType> BaseGraph<NodeType, GraphType, V>::getInNodesInternal(std::shared_ptr<Key> node,
                                                                            DirectedGraphType type) const
{
    // For a directed graph type this feature is not supported!
    return {};
}

template<class NodeType, class GraphType, typename V>
std::vector<NodeType> BaseGraph<NodeType, GraphType, V>::getInNodesInternal(std::shared_ptr<Key> node,
                                                                            BidirectionalGraphType type) const
{
    std::vector<NodeType> ret;

    // Check whether given node key has representation node in the graph
    auto searchNode = myBiMappingOfNodeDescriptorAndKey.right.find(node);

    if(searchNode != myBiMappingOfNodeDescriptorAndKey.right.end())
    {
        // Iterate through in-edges (the connections that are reaching on the given node:  X -> node)
        typename InternalGraph::in_edge_iterator neighbourIt;
        typename InternalGraph::in_edge_iterator neighbourEnd;
        boost::tie(neighbourIt, neighbourEnd) =
            boost::in_edges(myBiMappingOfNodeDescriptorAndKey.right.at(node), myGraph);

        for(; neighbourIt != neighbourEnd; ++neighbourIt)
        {
            // Get the source vertice of the in-edge, that will represent the in-node
            InternalNodeDescriptor noDescriptor = boost::source(*neighbourIt, myGraph);
            ret.push_back(myGraph[noDescriptor]);
        }
    }

    return ret;
}

template<class NodeType, class GraphType, typename V>
std::vector<std::shared_ptr<Key>> BaseGraph<NodeType, GraphType, V>::getInNodesKeys(std::shared_ptr<Key> node) const
{
    // Call the overloaded internal function that, depending on the graph type the implementation is supported or not
    return getInNodesKeysInternal(node, GraphType{});
}

template<class NodeType, class GraphType, typename V>
std::vector<std::shared_ptr<Key>> BaseGraph<NodeType, GraphType, V>::getInNodesKeysInternal(std::shared_ptr<Key> node,
                               DirectedGraphType type) const
{
    // For a directed graph type this feature is not supported!
    return {};
}

template<class NodeType, class GraphType, typename V>
std::vector<std::shared_ptr<Key>> BaseGraph<NodeType, GraphType, V>::getInNodesKeysInternal(std::shared_ptr<Key> node,
                               BidirectionalGraphType type) const
{
    std::vector<std::shared_ptr<Key>> ret;

    // Check whether given node key has representation node in the graph
    auto searchNode = myBiMappingOfNodeDescriptorAndKey.right.find(node);

    if(searchNode != myBiMappingOfNodeDescriptorAndKey.right.end())
    {
        // Iterate through in-edges (the connections that are reaching on the given node:  X -> node)
        typename InternalGraph::in_edge_iterator neighbourIt;
        typename InternalGraph::in_edge_iterator neighbourEnd;
        boost::tie(neighbourIt, neighbourEnd) =
            boost::in_edges(myBiMappingOfNodeDescriptorAndKey.right.at(node), myGraph);

        for(; neighbourIt != neighbourEnd; ++neighbourIt)
        {
            // Get the source vertice of the in-edge, that will represent the in-node
            InternalNodeDescriptor noDescriptor = boost::source(*neighbourIt, myGraph);
            ret.push_back(myBiMappingOfNodeDescriptorAndKey.left.at(noDescriptor));
        }
    }

    return ret;
}

template<class NodeType, class GraphType, typename V>
std::pair<bool, NodeType> BaseGraph<NodeType, GraphType, V>::getNode(std::shared_ptr<Key> nodeKey) const
{
    std::pair<bool, NodeType> ret;
    ret.first = false; // default: not found

    std::shared_lock<RecursiveSharedMutex> lock(myMutex);

    auto searchNode = myBiMappingOfNodeDescriptorAndKey.right.find(nodeKey);

    if(searchNode != myBiMappingOfNodeDescriptorAndKey.right.end())
    {
        ret.first  = true;
        ret.second = myGraph[myBiMappingOfNodeDescriptorAndKey.right.at(nodeKey)];
    }

    return ret;
}

template<class NodeType, class GraphType, typename V>
std::pair<bool, NodeType&> BaseGraph<NodeType, GraphType, V>::nodeAt(std::shared_ptr<Key> nodeKey) const
{
    std::shared_lock<RecursiveSharedMutex> lock(myMutex);

    auto searchNode = myBiMappingOfNodeDescriptorAndKey.right.find(nodeKey);

    if(searchNode != myBiMappingOfNodeDescriptorAndKey.right.end())
    {
        return {true, myGraph[myBiMappingOfNodeDescriptorAndKey.right.at(nodeKey)]};
    }

    static NodeType dummyNode;
    return {false, dummyNode};
}

template<class NodeType, class GraphType, typename V>
bool BaseGraph<NodeType, GraphType, V>::runDfs(std::shared_ptr<Key> rootNode,
                                               const BaseGraphDfsVisitorInterface<NodeType>& dfsVisitor)
{
    // Will lock mutex in shared mode in order to enable multiple-threads runDfs at same time
    // (default lock mode: shared)
    return internalRunDfs<std::shared_lock>(rootNode, dfsVisitor);
}

template<class NodeType, class GraphType, typename V>
bool BaseGraph<NodeType, GraphType, V>::runDfs(std::shared_ptr<Key> rootNode,
                                               const BaseGraphDfsVisitorInterface<NodeType>& dfsVisitor,
                                               bool exclusiveMode)
{
    if(exclusiveMode)
    {
        // Will lock mutex in exclusive mode, disabling multiple-threads to runDfs at same time
        return internalRunDfs<std::lock_guard>(rootNode, dfsVisitor);
    }
    else
    {
        // Will lock mutex in shared mode in order to enable multiple-threads runDfs at same time
        return internalRunDfs<std::shared_lock>(rootNode, dfsVisitor);
    }
}

template<class NodeType, class GraphType, typename V>
bool BaseGraph<NodeType, GraphType, V>::runBfs(std::shared_ptr<Key> rootNode,
                                               const BaseGraphBfsVisitorInterface<NodeType>& bfsVisitor)
{
    // Will lock mutex in shared mode in order to enable multiple-threads runBfs at same time
    // (default lock mode: shared)
    return internalRunBfs<std::shared_lock>(rootNode, bfsVisitor);
}

template<class NodeType, class GraphType, typename V>
bool BaseGraph<NodeType, GraphType, V>::runBfs(std::shared_ptr<Key> rootNode,
                                               const BaseGraphBfsVisitorInterface<NodeType>& bfsVisitor,
                                               bool exclusiveMode)
{
    if(exclusiveMode)
    {
        // Will lock mutex in exclusive mode, disabling multiple-threads to runBfs at same time
        return internalRunBfs<std::lock_guard>(rootNode, bfsVisitor);
    }
    else
    {
        // Will lock mutex in shared mode in order to enable multiple-threads runBfs at same time
        return internalRunBfs<std::shared_lock>(rootNode, bfsVisitor);
    }
}

template<class NodeType, class GraphType, typename V>
template< template<typename MT> class MutexLockType>
bool BaseGraph<NodeType, GraphType, V>::internalRunDfs(std::shared_ptr<Key> rootNode,
                                                       const BaseGraphDfsVisitorInterface<NodeType>& dfsVisitor)
{
    bool ret = false;

    MutexLockType<RecursiveSharedMutex> lock(myMutex);

    // Get the rootNode associated vertice_descriptor using the class member bimap, that
    // is a cache that maps a key to a vertice_descriptor

    // Check whether given rootNode key has representation node in the graph
    auto searchNode = myBiMappingOfNodeDescriptorAndKey.right.find(rootNode);

    if(searchNode != myBiMappingOfNodeDescriptorAndKey.right.end())
    {
        // Launch the DFS search algorithm starting on the given rootNode
        // The 2nd parameter of boost::depth_first_visit is the vertice_descriptor that
        // represents the starting point of the search
        boost::depth_first_visit(myGraph,
                                 myBiMappingOfNodeDescriptorAndKey.right.at(rootNode),
                                 GraphDfsGenericVisitor(dfsVisitor, *this),
                                 boost::make_vector_property_map<boost::default_color_type>(boost::get(boost::vertex_index,
                                         myGraph)));
        ret = true;
    }

    return ret;
}

template<class NodeType, class GraphType, typename V>
template< template<typename MT> class MutexLockType>
bool BaseGraph<NodeType, GraphType, V>::internalRunBfs(std::shared_ptr<Key> rootNode,
                                                       const BaseGraphBfsVisitorInterface<NodeType>& bfsVisitor)
{
    bool ret = false;

    MutexLockType<RecursiveSharedMutex> lock(myMutex);

    // Get the rootNode associated vertice_descriptor using the class member bimap, that
    // is a cache that maps a key to a vertice_descriptor

    // Check whether given rootNode key has representation node in the graph
    auto searchNode = myBiMappingOfNodeDescriptorAndKey.right.find(rootNode);

    if(searchNode != myBiMappingOfNodeDescriptorAndKey.right.end())
    {
        // Launch the BFS search algorithm starting on the given rootNode
        // The 2nd parameter of boost::breadth_first_search is the vertice_descriptor that
        // represents the starting point of the search
        boost::breadth_first_search(myGraph,
                                    myBiMappingOfNodeDescriptorAndKey.right.at(rootNode),
                                    boost::visitor(GraphBfsGenericVisitor(bfsVisitor, *this)));
        ret = true;
    }

    return ret;
}

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::renderToGraphviz(std::ostream& out) const
{
    boost::dynamic_properties dp;
    dp.property("node_id", get(boost::vertex_index, myGraph));
    dp.property("color", boost::get(&BaseNode::color, myGraph));
    dp.property("label", boost::get(&BaseNode::label, myGraph));

    std::shared_lock<RecursiveSharedMutex> lock(myMutex);
    boost::write_graphviz_dp(out, myGraph, dp);
}

// private members
template<class NodeType, class GraphType, typename V>
typename BaseGraph<NodeType, GraphType, V>::InternalNodeDescriptor BaseGraph<NodeType, GraphType, V>::addNodeToGraph(
    std::shared_ptr<Key> nodeKey,
    const NodeType& node)
{
    InternalNodeDescriptor ret;

    // Adding node to graph if NOT exists
    auto searchNode = myBiMappingOfNodeDescriptorAndKey.right.find(nodeKey);

    if(searchNode != myBiMappingOfNodeDescriptorAndKey.right.end())
    {
        // Already exists.. just store for return value
        ret = (*searchNode).second; // std::pair<const Key, long unsigned int>
    }
    else // NOT FOUND! need to be added!
    {
        ret = boost::add_vertex(node, myGraph);
        // Register mapping: InternalNodeDescriptor <-> Key
        myBiMappingOfNodeDescriptorAndKey.insert(NodeKeyMappingType(ret, nodeKey));
    }

    return ret;
}

template<class NodeType, class GraphType, typename V>
bool BaseGraph<NodeType, GraphType, V>::addConnectionToGraph(std::shared_ptr<Key> fromNodeKey, const NodeType& fromNode,
                                                             std::shared_ptr<Key> toNodeKey, const NodeType& toNode)
{
    bool ret = false;

    // Adding node and connections needs exclusive access to graph
    std::lock_guard<RecursiveSharedMutex> lock(myMutex);

    // Adding nodes to graph (internal check: if already exists no nothing)
    InternalNodeDescriptor outNodeDesc = addNodeToGraph(fromNodeKey, fromNode);
    InternalNodeDescriptor inNodeDesc  = addNodeToGraph(toNodeKey, toNode);

    // Finally, adding the connection between nodes, if not exists already
    // - If an edge from vertex u to vertex v exists,
    //     boost::edge return a pair containing one such edge and true.
    //     If there are no edges between u and v, return a pair with an arbitrary edge descriptor and false.
    if(false == boost::edge(outNodeDesc, inNodeDesc, myGraph).second)
    {
        boost::add_edge(outNodeDesc, inNodeDesc, myGraph);
        ret = true;
    }

    return ret;
}

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::deleteNodesMarkedAsTobeDeleted()
{
    // Remove all nodes, from the graph, that are marked as to be 'deleted'
    typename InternalGraph::vertex_iterator vIt;
    typename InternalGraph::vertex_iterator vEnd;
    boost::tie(vIt, vEnd) = boost::vertices(myGraph);

    while(vIt != vEnd)
    {
        if(myGraph[*vIt].deleted)
        {
            boost::clear_vertex(*vIt, myGraph); // 1st remove all connections to and from node
            boost::remove_vertex(*vIt, myGraph); // 2nd remove node from the the graph
            boost::tie(vIt, vEnd) = boost::vertices(myGraph);
        }
        else
        {
            ++vIt;
        }
    }

    // vertices descriptor are no longer valid => delete associative mapping
    myBiMappingOfNodeDescriptorAndKey.clear();

    // Reload internal property mappings based on the node descriptor : Key<=>Node descriptor
    // This is needed because Boost built-in vertex_index_t property for each node is renumbered so that after the
    // delete operation the node indices still form a contiguous range [0, num_vertices(g))
    for(boost::tie(vIt, vEnd) = boost::vertices(myGraph); vIt != vEnd; ++vIt)
    {
        const NodeType& nodeObj = myGraph[*vIt];
        // Register mapping: InternalNodeDescriptor <-> Key
        myBiMappingOfNodeDescriptorAndKey.insert(NodeKeyMappingType(*vIt, nodeObj.key));
    }
}

// ///////////////////////////////
// GraphDfsVisitor implementation
// ///////////////////////////////
template<class NodeType, class GraphType, typename V>
BaseGraph<NodeType, GraphType, V>::GraphDfsGenericVisitor::GraphDfsGenericVisitor(const
        BaseGraphDfsVisitorInterface<NodeType>&
        visitor,
        const BaseGraph& graphRef)
    : customDfsVisitor(visitor)
    , baseGraph(graphRef)
    , startNode(false)
{};

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::GraphDfsGenericVisitor::start_vertex(int s, const InternalGraph& g) const
{
    // Flag current node as start node to avoid manage the suppression state
    // This is only temporary state => is cleared (false) when start node is discover_vertex
    startNode = true;
    // Execute visitor custom code
    customDfsVisitor.onStartNode(*baseGraph.myBiMappingOfNodeDescriptorAndKey.left.at(s), g[s]);
}

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::GraphDfsGenericVisitor::discover_vertex(int v, const InternalGraph& g) const
{
    // Execute visitor custom code
    customDfsVisitor.onDiscoverNode(startNode, *baseGraph.myBiMappingOfNodeDescriptorAndKey.left.at(v), g[v]);
    startNode = false;
}

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::GraphDfsGenericVisitor::back_edge(InternalEdgeDescriptor e,
                                                                          const InternalGraph& g) const
{
    // Execute visitor custom code
    int sourceVertex = boost::source(e, g);
    int targetVertex = boost::target(e, g);

    customDfsVisitor.onBackConnection(*baseGraph.myBiMappingOfNodeDescriptorAndKey.left.at(sourceVertex), g[sourceVertex],
                                      *baseGraph.myBiMappingOfNodeDescriptorAndKey.left.at(targetVertex), g[targetVertex]);
}

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::GraphDfsGenericVisitor::finish_vertex(int u, const InternalGraph& g) const
{
    // Execute visitor custom code
    customDfsVisitor.onFinishNode(*baseGraph.myBiMappingOfNodeDescriptorAndKey.left.at(u), g[u]);
}

// ///////////////////////////////
// GraphBfsVisitor implementation
// ///////////////////////////////
template<class NodeType, class GraphType, typename V>
BaseGraph<NodeType, GraphType, V>::GraphBfsGenericVisitor::GraphBfsGenericVisitor(const
        BaseGraphBfsVisitorInterface<NodeType>&
        visitor,
        const BaseGraph& graphRef)
    : customBfsVisitor(visitor)
    , baseGraph(graphRef)
    , startNode(true) // The first discovered node is the start node
    , numberOfDiscovered(0)
    , numberOfFinished(0)
{};

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::GraphBfsGenericVisitor::discover_vertex(int v, const InternalGraph& g) const
{
    // Count the number of nodes being discovered in the graph
    // Because the discover of a vertice happens before it is declared finished (all ajacent nodes were already discovered)
    // this counter will be later used to determine whether a finished node (see finish_vertex callback) is the last node
    // discovered in the graph
    numberOfDiscovered++;

    if(startNode)
    {
        customBfsVisitor.onStartNode(*baseGraph.myBiMappingOfNodeDescriptorAndKey.left.at(v), g[v]);
    }

    customBfsVisitor.onDiscoverNode(startNode, *baseGraph.myBiMappingOfNodeDescriptorAndKey.left.at(v), g[v]);
    startNode = false;
}

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::GraphBfsGenericVisitor::finish_vertex(int u, const InternalGraph& g) const
{
    // Count the number of nodes where all ajacent nodes were already discovered (commonly referred in boost by finished vertex)
    numberOfFinished++;

    customBfsVisitor.onFinishNode(*baseGraph.myBiMappingOfNodeDescriptorAndKey.left.at(u), g[u]);

    // The end of the BFS search is declared when all discovered nodes has been declared finished
    if(numberOfDiscovered == numberOfFinished)
    {
        customBfsVisitor.onEndSearch(*baseGraph.myBiMappingOfNodeDescriptorAndKey.left.at(u), g[u]);
    }
}

// /////////////////////////////////////
// GraphDfsDeleteVisitor implementation
// /////////////////////////////////////
template<class NodeType, class GraphType, typename V>
BaseGraph<NodeType, GraphType, V>::GraphDfsDeleteVisitor::GraphDfsDeleteVisitor()
{
}

template<class NodeType, class GraphType, typename V>
void BaseGraph<NodeType, GraphType, V>::GraphDfsDeleteVisitor::discover_vertex(int v, const InternalGraph& g) const
{
    g[v].deleted = true;
}

