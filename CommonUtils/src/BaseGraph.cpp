#include <string>
#include "CommonUtils/BaseGraph.h"

// ///////////////////////////
// BaseNode Implementation
// ///////////////////////////

const std::string globalNodeColorRefs[] = {"red", "yellow", "grey", "black", "blue", "green"};

BaseNode::BaseNode()
    : key(std::make_shared<Key>())
    , label("-") // default node label
    , color(globalNodeColorRefs[static_cast<int>(NodeColor::BLACK)])  // default node color
    , deleted(false)
{}

BaseNode::BaseNode(std::shared_ptr<Key> k)
    : key(k)
    , label(key->getShortDescription())
    , color(globalNodeColorRefs[static_cast<int>(NodeColor::BLACK)])  // default node color
    , deleted(false)
{}

BaseNode::BaseNode(std::shared_ptr<Key> k, const std::string& name, const NodeColor& c)
    : key(k)
    , label(name)
    , color(globalNodeColorRefs[static_cast<int>(c)])
    , deleted(false)
{}

BaseNode::BaseNode(const BaseNode& node)
    : key(node.key)
    , label(node.label)
    , color(node.color)
    , deleted(node.deleted)
{}

const BaseNode& BaseNode::setLabel(const std::string& pLabel)
{
    label = pLabel;
    return *this;
}

const BaseNode& BaseNode::setColor(NodeColor pColor) const
{
    color = globalNodeColorRefs[static_cast<int>(pColor)];
    return *this;
}

