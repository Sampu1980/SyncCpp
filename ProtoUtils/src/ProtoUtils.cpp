#include "ProtoUtils/ProtoUtils.h"
#include "logger.h"

#include <google/protobuf/message.h>
#include <google/protobuf/field_mask.pb.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/util/field_mask_util.h>

#include <string>
#include <unordered_set>
#include <cstddef>
#include <stdexcept>
#include <iostream>

using google::protobuf::Message;
using google::protobuf::FieldMask;
using google::protobuf::Descriptor;
using google::protobuf::Reflection;
using google::protobuf::FieldDescriptor;
using google::protobuf::util::FieldMaskUtil;

using std::string;
using std::unordered_set;
using std::size_t;
using std::runtime_error;
namespace ProtoUtils
{
    // Primitive datatypes as defined in google.protobuf.wrappers.proto
    static const unordered_set<string> datatypes =
    {
        "google.protobuf.DoubleValue",
        "google.protobuf.FloatValue",
        "google.protobuf.Int64Value",
        "google.protobuf.UInt64Value",
        "google.protobuf.Int32Value",
        "google.protobuf.UInt32Value",
        "google.protobuf.BoolValue",
        "google.protobuf.StringValue",
        "google.protobuf.BytesValue"
    };

    void GetFieldPathFromProto(const Message& objMsg,
                               unordered_set<string>& fieldDsSet,
                               string prefixStr)
    {
        const Descriptor* desc = objMsg.GetDescriptor();

        // Very unlikely to occur. Usually occurs due to some critical issue,
        // eg - build time issues while including proto generated files
        if(desc == NULL)
        {
            throw runtime_error("Cannot get descriptor from message");
        }

        const Reflection* refl = objMsg.GetReflection();

        for(int i = 0; i < desc->field_count(); i++)
        {
            string retStr = "";
            const FieldDescriptor* fieldDes = desc->field(i);

            if(prefixStr != "")
            {
                retStr = prefixStr + ".";
            }

            retStr += fieldDes->name();

            //Ignore repeated fields (lists and maps)
            if(fieldDes->is_repeated())
            {
                continue;
            }

            if(fieldDes->type() == FieldDescriptor::TYPE_MESSAGE)
            {
                //null check
                if(!refl->HasField(objMsg, fieldDes))
                {
                    continue;
                }

                const Message& fieldMsg = refl->GetMessage(objMsg, fieldDes);

                if(datatypes.find(fieldMsg.GetDescriptor()->full_name())
                   != datatypes.end())
                {
                    fieldDsSet.insert(retStr);
                }
                else
                {
                    GetFieldPathFromProto(fieldMsg, fieldDsSet, retStr);
                }
            }
        }//end for
    }//end fn

    unordered_set<string> GetFieldPathStringFromProto(const Message& objMsg)
    {
        unordered_set<string> fieldDsSet;
        GetFieldPathFromProto(objMsg, fieldDsSet, "");

        return fieldDsSet;
    }

    void GetFieldMaskFromString(unordered_set<string>& attrPath, FieldMask& mask)
    {
        unordered_set<string>::iterator iter;

        for(iter = attrPath.begin(); iter != attrPath.end(); iter++)
        {
            mask.add_paths(*iter);
        }
    }

    void MergeMessages(Message const& srcMsg,
                       Message const& preUpdateMsg,
                       Message& mergedMsg)
    {
        /* Logic
           1. Get field mask of primitive types from srcMsg = boolsMask
           2. Get allFieldsMask from srcMsg
           3. diffMask = allFieldsMask - boolsMask
           4. Apply diffMask to preUpdateMsg -> Store in mergedMsg
           5. Merge srcMsg into mergedMsg
         */

        string jsonString;
        FieldMask boolsMask, allFieldsMask, diffMask;

        // (1)
        unordered_set<string> field_path_string = GetFieldPathStringFromProto(srcMsg);
        GetFieldMaskFromString(field_path_string, boolsMask);
        APP_STRACE("boolsMask: " << FieldMaskUtil::ToString(boolsMask));

        // (2)
        FieldMaskUtil::GetFieldMaskForAllFields(srcMsg.GetDescriptor(), &allFieldsMask);
        APP_STRACE("allFieldsMask: " << FieldMaskUtil::ToString(allFieldsMask));

        // (3)
        FieldMaskUtil::Subtract(srcMsg.GetDescriptor(), allFieldsMask, boolsMask, &diffMask);
        APP_STRACE("diffMask: " << FieldMaskUtil::ToString(diffMask));

        // (4)
        FieldMaskUtil::MergeOptions options = FieldMaskUtil::MergeOptions();
        FieldMaskUtil::MergeMessageTo(preUpdateMsg, diffMask, options, &mergedMsg);

        // (5)
        mergedMsg.MergeFrom(srcMsg);
    }
} // namespace ProtoUtils
