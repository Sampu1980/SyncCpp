#include <functional>
#include <string>
#include <map>
#include <mutex>
#include "CommonUtils/Key.h"
#include "CommonUtils/Utils.h"

/// Storage for the human readable description of the entity member
static std::map<std::string, std::string> myEntityMapStr;
/// Mutex for concurrent access over myEntityMapStr
static std::mutex myAccessEntityMapMutex;

// class Key implementation
Key::Key()
    : myEntity("")
    , myType("")
    , myIsBinary(false)
    , myDescription("")
    , myEntityView(myEntity)
    , myTypeView(myType)
    , myDescriptionView(myDescription)
{
}

Key::Key(const std::string& entity, const std::string& type, bool isBinary)
    : myEntity(entity)
    , myType(type)
    , myIsBinary(isBinary)
    , myEntityView(myEntity)
    , myTypeView(myType)
{
    // Store the human readable description of the entity member in a static storage
    // avoid the bin2hex conversion of the entity member each time a new key is created, if another key was already created using the same entity
    {
        std::lock_guard<std::mutex> lock(myAccessEntityMapMutex);
        auto search = myEntityMapStr.find(myEntity);

        if(search == myEntityMapStr.end())
        {
            myEntityMapStr[myEntity]  = (myIsBinary ? commonUtils::asHexString(myEntity) : myEntity);
        }
    }

    myDescription = calculateDescription();
    myDescriptionView = myDescription;
}

Key::Key(const Key& key)
    : myEntity(key.myEntity)
    , myType(key.myType)
    , myIsBinary(key.myIsBinary)
    , myDescription(key.myDescription)
    , myEntityView(myEntity)
    , myTypeView(myType)
    , myDescriptionView(myDescription)
{
}

Key::Key(const Key& aKey, const std::string& aType)
    : myEntity(aKey.myEntity)
    , myType(aType)
    , myIsBinary(aKey.myIsBinary)
    , myDescription(calculateDescription())
    , myEntityView(myEntity)
    , myTypeView(myType)
    , myDescriptionView(myDescription)
{
}

std::string Key::calculateDescription()
{
    std::lock_guard<std::mutex> lock(myAccessEntityMapMutex);
    return (myType + "/" + myEntityMapStr[myEntity]);
}

std::string Key::getEntity() const
{
    return myEntityView.to_string();
}

std::string Key::getType() const
{
    return myTypeView.to_string();
}

std::string Key::getShortDescription() const
{
    return myDescriptionView.to_string();
}

bool Key::operator==(const Key& rhs) const
{
    return (myEntity == rhs.myEntity && myType == rhs.myType);
}

bool Key::operator!=(const Key& rhs) const
{
    return ! operator==(rhs);
}

Key& Key::operator=(const Key& rhs)
{
    if(rhs != *this)
    {
        myEntity      = rhs.myEntity;
        myType        = rhs.myType;
        myIsBinary    = rhs.myIsBinary;
        myDescription = rhs.myDescription;

        myEntityView = myEntity;
        myTypeView = myType;
        myDescriptionView = myDescription;
    }

    return *this;
}

bool Key::isValid() const
{
    return (!myEntity.empty() && !myType.empty());
}

bool Key::compareEntity(const Key& rhs) const
{
    return myEntityView == rhs.myEntityView;
}

bool Key::compareType(const Key& rhs) const
{
    return myTypeView == rhs.myTypeView;
}

std::size_t Key::calculatePolymorphicHash() const noexcept
{
    return KeyHasher{}.operator()(*this);
}

const std::string& Key::getReadableEntity()
{
    std::lock_guard<std::mutex> lock(myAccessEntityMapMutex);
    return myEntityMapStr[myEntity];
}

// class KeyHasher implementation
std::size_t KeyHasher::operator()(const Key& key) const noexcept
{
    // Calculate a 32-bit hash and cast it to size_t, which is platform dependent
    // This mechanism will be supported both on 32-bit and 64-bit

    uint32_t h1 = commonUtils::hashFnv1a(key.getEntity());
    uint32_t h2 = commonUtils::hashFnv1a(key.getType());
    uint32_t ret = h1 ^ (h2 << 1);

    return ret;
}

// class PolymorphicKeyHasher implementation
std::size_t PolymorphicKeyHasher::operator()(const Key& key) const noexcept
{
    return key.calculatePolymorphicHash();
}

std::size_t PolymorphicKeyHasher::operator()(std::shared_ptr<Key> key) const noexcept
{
    return key->calculatePolymorphicHash();
}
