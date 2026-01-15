// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BloomFilter - Avalanche-Optimized Bloom Filter Library
/// @notice Space-efficient probabilistic data structure with Avalanche-style optimizations
/// @dev Implements compiler hints, bit rotation, and accumulator patterns for maximum efficiency
library BloomFilter {
    /// @notice Constants (aligned with Avalanche mainnet)
    uint8 private constant BITS_PER_BYTE = 8;
    uint8 private constant HASH_ROTATION = 17;
    uint8 private constant MIN_HASHES = 1;
    uint8 private constant MAX_HASHES = 16;

    /// @notice Avalanche-aligned Bloom filter structure
    struct Filter {
        uint256[] entries; // Packed bit storage
        uint64 numBits; // Total bits
        uint64[] hashSeeds; // Random seeds for hash functions
        uint32 count; // Number of elements added
        uint8 numHashes; // Number of hash functions
    }

    /// @notice Errors
    error FilterNotInitialized();
    error TooFewHashes(uint8 provided, uint8 minimum);
    error TooManyHashes(uint8 provided, uint8 maximum);
    error TooFewEntries(uint32 provided, uint32 minimum);

    /// @notice Initialize Bloom filter
    /// @param filter The bloom filter to initialize
    /// @param numBytes Number of bytes for storage
    /// @param numHashes Number of hash functions (1-16)
    function initialize(Filter storage filter, uint32 numBytes, uint8 numHashes) internal {
        if (numBytes < 1) revert TooFewEntries(numBytes, 1);
        if (numHashes < MIN_HASHES) revert TooFewHashes(numHashes, MIN_HASHES);
        if (numHashes > MAX_HASHES) revert TooManyHashes(numHashes, MAX_HASHES);

        // Generate random seeds
        filter.hashSeeds = new uint64[](numHashes);
        for (uint256 i = 0; i < numHashes;) {
            filter.hashSeeds[i] =
                uint64(uint256(keccak256(abi.encode(block.timestamp, block.prevrandao, i))));
            unchecked {
                ++i;
            }
        }

        // Pack bytes into uint256 words for efficiency
        filter.entries = new uint256[]((numBytes + 31) / 32);
        filter.numBits = uint64(numBytes) * BITS_PER_BYTE;
        filter.numHashes = numHashes;
        filter.count = 0;
    }

    /// @notice Add element to filter (Avalanche-aligned with compiler hints)
    /// @param filter The bloom filter
    /// @param hash The hash to add
    function add(Filter storage filter, bytes32 hash) internal {
        if (filter.numBits == 0) revert FilterNotInitialized();

        uint64 h = uint64(uint256(hash));
        uint64 numBits = filter.numBits;

        // Avalanche compiler hint: eliminate division-by-zero checks
        unchecked {
            uint64 compilerHint = 1 % numBits;
            compilerHint; // Suppress unused variable warning
        }

        // Avalanche pattern: bit rotation + XOR with seeds
        for (uint256 i = 0; i < filter.numHashes;) {
            h = _rotateLeft64(h, HASH_ROTATION) ^ filter.hashSeeds[i];

            unchecked {
                uint64 bitIndex = h % numBits;
                uint256 wordIndex = bitIndex / 256;
                uint256 bitPosition = bitIndex % 256;

                filter.entries[wordIndex] |= uint256(1) << bitPosition;
                ++i;
            }
        }

        filter.count++;
    }

    /// @notice Check if element exists (Avalanche accumulator pattern)
    /// @param filter The bloom filter
    /// @param hash The hash to check
    /// @return True if element might exist (false positive possible)
    function contains(Filter storage filter, bytes32 hash) internal view returns (bool) {
        if (filter.numBits == 0) revert FilterNotInitialized();

        uint64 h = uint64(uint256(hash));
        uint64 numBits = filter.numBits;

        // Avalanche compiler hint
        unchecked {
            uint64 compilerHint = 1 % numBits;
            compilerHint;
        }

        // Avalanche accumulator pattern with early exit
        uint256 accumulator = 1;

        for (uint256 i = 0; i < filter.numHashes && accumulator != 0;) {
            h = _rotateLeft64(h, HASH_ROTATION) ^ filter.hashSeeds[i];

            unchecked {
                uint64 bitIndex = h % numBits;
                uint256 wordIndex = bitIndex / 256;
                uint256 bitPosition = bitIndex % 256;

                accumulator &= (filter.entries[wordIndex] >> bitPosition) & 1;
                ++i;
            }
        }

        return accumulator != 0;
    }

    /// @notice Add contract address
    function addAddress(Filter storage filter, address addr) internal {
        add(filter, keccak256(abi.encodePacked(addr)));
    }

    /// @notice Check contract address
    function containsAddress(Filter storage filter, address addr) internal view returns (bool) {
        return contains(filter, keccak256(abi.encodePacked(addr)));
    }

    /// @notice Batch add addresses
    function batchAddAddresses(Filter storage filter, address[] calldata addresses) internal {
        if (filter.numBits == 0) revert FilterNotInitialized();

        for (uint256 i = 0; i < addresses.length;) {
            addAddress(filter, addresses[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Get filter statistics
    function getStats(Filter storage filter)
        internal
        view
        returns (uint64 numBits, uint8 numHashes, uint32 count)
    {
        return (filter.numBits, filter.numHashes, filter.count);
    }

    /// @notice Avalanche-style 64-bit left rotation
    function _rotateLeft64(uint64 value, uint8 rotation) private pure returns (uint64) {
        uint64 rot = uint64(rotation % 64);
        return (value << rot) | (value >> (64 - rot));
    }
}
