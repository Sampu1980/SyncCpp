#ifndef PROTOUTILS_H
#define PROTOUTILS_H
#include <google/protobuf/message.h>
#include <google/protobuf/field_mask.pb.h>

#include <string>
#include <unordered_set>

namespace ProtoUtils
{
    /**
    * @brief Function to get primitive datatype paths set in a message
    *        Primitive datatypes are defined in google/protobuf/wrappers.proto
    *        Does not support maps and lists
    *
    * @param[in] objMsg Proto object reference
    *
    * @param[out] fieldDsSet Set of field descriptor names
    *
    * @param[in]  prefixstr Root path in top level message
    */
    void GetFieldPathFromProto(const google::protobuf::Message& objMsg,
                               std::unordered_set<std::string>& fieldDsSet,
                               std::string prefixStr);

    /**
    * @brief Function to get field paths as a single comma separated string
    *       Fields should be set to some value to be counted in descriptor list
    *
    * @param[in] objMsg Proto object reference
    *
    * @return std::unordered_set<std::string> set of paths of fields set in msg
    */
    std::unordered_set<std::string> GetFieldPathStringFromProto(
        const google::protobuf::Message& objMsg);

    /**
    * @brief Function to get field mask from comma separated string of paths
    *
    * @param[in] attrPaths Set of field paths
    *
    * @param[out] mask Fieldmask object
    */
    void GetFieldMaskFromString(std::unordered_set<std::string>& attrPaths,
                                google::protobuf::FieldMask& mask);

    /**
    * @brief Function to merge src msg into dest msg and report as merged message
    *
    * @param[in] srcMsg Reference to src protobuf message
    *
    * @param[in] preUpdateMsg Pointer to destination message
    *
    * @param[out] mergeMsg Pointer to difference message
    */
    void MergeMessages(google::protobuf::Message const& srcMsg,
                       google::protobuf::Message const& preUpdateMsg,
                       google::protobuf::Message& mergeMsg);
}//ProtoUtils
#endif //PROTO_UTILS


