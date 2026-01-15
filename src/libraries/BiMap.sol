// SPDX-License-Identifier: MIT
// Based on Avalanche's BiMap implementation
// Copyright (C) 2019-2024, Ava Labs, Inc. All rights reserved.
pragma solidity ^0.8.24;

/**
 * @title BiMap
 * @notice Gas-optimized bi-directional mapping library
 * @dev Maintains 1:1 relationship between keys and values with O(1) reverse lookup
 *
 * Key Features:
 * - Bijective mapping (enforces one-to-one relationship)
 * - Dual indexes for forward and reverse lookups
 * - Automatic conflict resolution (removes old entries on collision)
 * - Gas-optimized with packed storage patterns
 */
library BiMap {
    /// @notice Emitted when an entry is added/updated
    event EntryPut(bytes32 indexed key, bytes32 indexed value);

    /// @notice Emitted when an entry is removed
    event EntryRemoved(bytes32 indexed key, bytes32 indexed value);

    error NotBijective();
    error KeyNotFound();
    error ValueNotFound();

    struct Map {
        mapping(bytes32 => bytes32) keyToValue;
        mapping(bytes32 => bytes32) valueToKey;
        uint256 length;
    }

    struct Entry {
        bytes32 key;
        bytes32 value;
    }

    /**
     * @notice Put a key-value pair into the map
     * @dev Removes 0, 1, or 2 existing entries to maintain bijection
     * @param map The BiMap storage reference
     * @param key The key to insert
     * @param value The value to insert
     * @return removed Array of removed entries (0-2 elements)
     */
    function put(Map storage map, bytes32 key, bytes32 value)
        internal
        returns (Entry[] memory removed)
    {
        // Pre-allocate max size (2 possible removals)
        removed = new Entry[](2);
        uint256 removedCount = 0;

        // Remove old value if key exists
        bytes32 oldValue = map.keyToValue[key];
        if (oldValue != bytes32(0)) {
            removed[removedCount++] = Entry({key: key, value: oldValue});
            delete map.valueToKey[oldValue];
            map.length--;
        }

        // Remove old key if value exists (and it's different from current key)
        bytes32 oldKey = map.valueToKey[value];
        if (oldKey != bytes32(0) && oldKey != key) {
            removed[removedCount++] = Entry({key: oldKey, value: value});
            delete map.keyToValue[oldKey];
            map.length--;
        }

        // Set new mapping
        map.keyToValue[key] = value;
        map.valueToKey[value] = key;
        map.length++;

        emit EntryPut(key, value);

        // Resize array to actual removed count
        /// @solidity memory-safe-assembly
        assembly {
            mstore(removed, removedCount)
        }

        return removed;
    }

    /**
     * @notice Get value by key
     */
    function getValue(Map storage map, bytes32 key)
        internal
        view
        returns (bytes32 value, bool exists)
    {
        value = map.keyToValue[key];
        exists = (value != bytes32(0));
    }

    /**
     * @notice Get key by value (reverse lookup)
     */
    function getKey(Map storage map, bytes32 value)
        internal
        view
        returns (bytes32 key, bool exists)
    {
        key = map.valueToKey[value];
        exists = (key != bytes32(0));
    }

    /**
     * @notice Check if key exists
     */
    function hasKey(Map storage map, bytes32 key) internal view returns (bool) {
        return map.keyToValue[key] != bytes32(0);
    }

    /**
     * @notice Check if value exists
     */
    function hasValue(Map storage map, bytes32 value) internal view returns (bool) {
        return map.valueToKey[value] != bytes32(0);
    }

    /**
     * @notice Delete entry by key
     */
    function deleteKey(Map storage map, bytes32 key)
        internal
        returns (bytes32 value, bool existed)
    {
        value = map.keyToValue[key];
        if (value == bytes32(0)) {
            return (bytes32(0), false);
        }

        delete map.keyToValue[key];
        delete map.valueToKey[value];
        map.length--;

        emit EntryRemoved(key, value);
        return (value, true);
    }

    /**
     * @notice Delete entry by value
     */
    function deleteValue(Map storage map, bytes32 value)
        internal
        returns (bytes32 key, bool existed)
    {
        key = map.valueToKey[value];
        if (key == bytes32(0)) {
            return (bytes32(0), false);
        }

        delete map.keyToValue[key];
        delete map.valueToKey[value];
        map.length--;

        emit EntryRemoved(key, value);
        return (key, true);
    }

    /**
     * @notice Get map length
     */
    function length(Map storage map) internal view returns (uint256) {
        return map.length;
    }
}

/**
 * @title AddressBiMap
 * @notice Specialized BiMap for address ↔ address mappings
 */
library AddressBiMap {
    using BiMap for BiMap.Map;

    function put(BiMap.Map storage map, address key, address value)
        internal
        returns (BiMap.Entry[] memory)
    {
        return map.put(bytes32(uint256(uint160(key))), bytes32(uint256(uint160(value))));
    }

    function getValue(BiMap.Map storage map, address key)
        internal
        view
        returns (address value, bool exists)
    {
        (bytes32 val, bool ex) = map.getValue(bytes32(uint256(uint160(key))));
        return (address(uint160(uint256(val))), ex);
    }

    function getKey(BiMap.Map storage map, address value)
        internal
        view
        returns (address key, bool exists)
    {
        (bytes32 k, bool ex) = map.getKey(bytes32(uint256(uint160(value))));
        return (address(uint160(uint256(k))), ex);
    }

    function hasKey(BiMap.Map storage map, address key) internal view returns (bool) {
        return map.hasKey(bytes32(uint256(uint160(key))));
    }

    function hasValue(BiMap.Map storage map, address value) internal view returns (bool) {
        return map.hasValue(bytes32(uint256(uint160(value))));
    }

    function deleteKey(BiMap.Map storage map, address key)
        internal
        returns (address value, bool existed)
    {
        (bytes32 val, bool ex) = map.deleteKey(bytes32(uint256(uint160(key))));
        return (address(uint160(uint256(val))), ex);
    }

    function deleteValue(BiMap.Map storage map, address value)
        internal
        returns (address key, bool existed)
    {
        (bytes32 k, bool ex) = map.deleteValue(bytes32(uint256(uint160(value))));
        return (address(uint160(uint256(k))), ex);
    }
}

/**
 * @title Uint256BiMap
 * @notice Specialized BiMap for uint256 ↔ uint256 mappings
 */
library Uint256BiMap {
    using BiMap for BiMap.Map;

    function put(BiMap.Map storage map, uint256 key, uint256 value)
        internal
        returns (BiMap.Entry[] memory)
    {
        return map.put(bytes32(key), bytes32(value));
    }

    function getValue(BiMap.Map storage map, uint256 key)
        internal
        view
        returns (uint256 value, bool exists)
    {
        (bytes32 val, bool ex) = map.getValue(bytes32(key));
        return (uint256(val), ex);
    }

    function getKey(BiMap.Map storage map, uint256 value)
        internal
        view
        returns (uint256 key, bool exists)
    {
        (bytes32 k, bool ex) = map.getKey(bytes32(value));
        return (uint256(k), ex);
    }

    function hasKey(BiMap.Map storage map, uint256 key) internal view returns (bool) {
        return map.hasKey(bytes32(key));
    }

    function hasValue(BiMap.Map storage map, uint256 value) internal view returns (bool) {
        return map.hasValue(bytes32(value));
    }

    function deleteKey(BiMap.Map storage map, uint256 key)
        internal
        returns (uint256 value, bool existed)
    {
        (bytes32 val, bool ex) = map.deleteKey(bytes32(key));
        return (uint256(val), ex);
    }

    function deleteValue(BiMap.Map storage map, uint256 value)
        internal
        returns (uint256 key, bool existed)
    {
        (bytes32 k, bool ex) = map.deleteValue(bytes32(value));
        return (uint256(k), ex);
    }
}
