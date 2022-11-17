#ifndef KEY_H
#define KEY_H

#include <string>
#include <boost/functional/hash.hpp>
#include <boost/utility/string_view.hpp>

/**
 * @class Key
 * @brief Identifier to uniquely represent an entity (e.g. faults, LEDs, other).
 */
class Key
{
    public:
        /**
         * Class Default Constructor
         */
        Key();

        /**
         * @brief Class Contructor
         * @param entity the entity that this Key relates to
         * @param type the type that this Key relates to
         * @param isBinary Indicates if the field entity is in binary format
         */
        Key(const std::string& entity, const std::string& type, bool isBinary = true);

        /**
         * @brief Copy constructor
         * @param key base key to copy from
         */
        Key(const Key& key);

        /**
         * @brief Custom Constructor that generate a new key based on provided key entity and given type.
         * @param aKey base key to copy entity from
         * @param aType the type for the new key
         */
        Key(const Key& aKey, const std::string& aType);

        /**
         * @brief Default destructor
         */
        ~Key() = default;

        /**
         * @brief Get entity
         * @return string with the entity
         */
        std::string getEntity() const;

        /**
         * @brief Get type
         * @return string with the type
         */
        std::string getType() const;

        /**
         * @brief Get Key short description
         * @return string with the description
         */
        virtual std::string getShortDescription() const;

        /**
         * @brief Operator ==
         * @param rhs second argument of comparison
         * @return true if equal comparison; false otherwise
         */
        virtual bool operator==(const Key& rhs) const;

        /**
         * @brief operator !=
         * @param rhs second argument of comparison
         * @return true if not equal comparison; false otherwise
         */
        bool operator!=(const Key& rhs) const;

        /**
         * @brief operator= Full assignment operation. Left hand side of the
         *        assignment will be a exact copy of rhs.
         * @param rhs source of assignment
         * @return reference to *this
         */
        Key& operator=(const Key& rhs);

        /**
         * @brief Check if this Key is valid (entity and type are not empty)
         * @return true if key is valid
         */
        bool isValid() const;

        /**
         * @brief Method to calculate a hash value for Key based object.
         * Derived class, expanding base Key with more variable members, shall override this method,
         * and calculate the hash taking into account those members.
         * @return a std::size_t representing the hash value
         */
        virtual std::size_t calculatePolymorphicHash() const noexcept;

        /**
         * @brief Compare entity
         * @param rhs second argument of comparison
         * @return true if equal comparison; false otherwise
         */
        bool compareEntity(const Key& rhs) const;

        /**
         * @brief Compare type
         * @param rhs second argument of comparison
         * @return true if equal comparison; false otherwise
         */
        bool compareType(const Key& rhs) const;

    protected:
        /**
         * @brief Method to calculate the description for Key based object
         * @return description returns a string with the key's description that's defined per
         *         myType + '/' + (HEX form of myEntity)
         */
        virtual std::string calculateDescription();

        /**
         * @brief Get human readable string form of the entity member
         * @return string with the entity
         */
        const std::string& getReadableEntity();

        std::string myEntity;      ///< Unique identifier (e.g. of a fault or a MO)
        std::string myType;        ///< Type identifier i.e. "OTU", "PORT", "LOS"

        bool myIsBinary;           ///< Indicates if the entity field is in binary format
        std::string myDescription; ///< Human readable description of the Key object

        /**
         * @note The introduction of the next string_view members is to restrain the
         *       copy string operation made on getter methods of myEntity, myType and myDescription members.
         *       It was observed that in case the corruption of data memory
         *       (the array that contains the sequence of characters including null terminator)
         *       of these strings, when using the getter methods, a copy is attempted to be made but std::bad_alloc
         *       is thrown. This is most likely to happen because the null terminator of the string has been overwritten
         *       and when the implementation tries to made a copy, it will try to find then next null terminator and might happen
         *       that the next one could only be found far MB away from the begin of the array, leading to a possible huge amount
         *       of bytes to be copied.
         *       The string_view will made a snapshot of each of these string by caching internally the begin (ptr) and
         *       the end (ptr + size) of the string sequence.
         *       When calling the getter methods, a string will be created (string_view::to_string) using the cached begin and end.
         *       This way, if the original string got corrupted, the copy will always be made based on the snapshot initially made.
         *
         * @note As mentioned above, string_view provides a snapshot like functionality of a given string.
         *       In case that string is modified hereafter the string_view will keep pointing to the initial sequence of charaters.
         *       e.g.
         *              1) string = "AAA"; string_view = string; print string_view => "AAA"
         *              2) string = "BBBB"; print string_view => "AAA"
         *          Typically if the new string assignment size is bigger than the previous, is noted that a new memory allocation is made,
         *          meaning that the sequence of characters of that string is in another address.
         *       The correct way to handle this situation is to update the string view as well, rightafter the new assigment:
         *       e.g.
         *              1) string = "AAA"; string_view = string; print string_view => "AAA"
         *              2) string = "BBBB"; string_view = string; print string_view => "BBBB"
         *
         */
        boost::string_view myEntityView;      ///< Provides a view of the myEntity string
        boost::string_view myTypeView;        ///< Provides a view of the myType string
        boost::string_view myDescriptionView; ///< Provides a view of the myDescription string
};

/**
 * @class KeyHasher
 * @brief Custom hash function for base Key class, acting as standalone function object.
 * - Takes a single argument key of type Key.
 * - Returns a value of type std::size_t that represents the hash value of Key object.
 */
class KeyHasher
{
    public:
        /**
         * @brief calculate the hash of the given Key argument
         * @param key the object to be hashed
         * @return a std::size_t representing the hash value
         */
        std::size_t operator()(const Key& key) const noexcept;
};

/**
 * @class PolymorphicKeyHasher
 * @brief Custom hash function for base Key class, acting as standalone function object.
 * - Takes a single argument key of type Key.
 * - Returns a value of type std::size_t that represents the hash value of Key object.
 */
class PolymorphicKeyHasher
{
    public:
        /**
         * @brief calculate the hash of the given Key argument
         * @param key the object to be hashed
         * @return a std::size_t representing the hash value
         */
        std::size_t operator()(const Key& key) const noexcept;
        std::size_t operator()(std::shared_ptr<Key> key) const noexcept;
};

namespace std
{
    // Inject into namespace std custom specialization of std::hash for Key object type
    // e.g. usage:
    // std::size_t hash = std::hash<Key>{}(obj);

    template<> struct hash<Key>
    {
        std::size_t operator()(Key const& key) const noexcept
        {
            return KeyHasher{}.operator()(key);
        }
    };

    // Inject into namespace std custom specialization of std::equal_to for MoKey and FaultKey types
    // This is required because unordered_map cannot rely on the fact that the a hash function will always provide a
    // unique hash value for every distinct key (to be able to deal with possible collisions),
    // so it needs a way to compare two given keys for an exact match.
    // the comparison uses both Entity and Type
    template<> struct equal_to<Key>
    {
        bool operator()(const Key& lhs, const Key& rhs) const
        {
            return (lhs.compareEntity(rhs) &&
                    lhs.compareType(rhs));
        }
    };

    // the comparison uses both Entity and Type from the shared ptr
    template<> struct equal_to<std::shared_ptr<Key>>
    {
        bool operator()(std::shared_ptr<Key> lhs, std::shared_ptr<Key> rhs) const
        {
            return lhs->calculatePolymorphicHash() == rhs->calculatePolymorphicHash();
        }
    };
}

#endif // KEY_H

