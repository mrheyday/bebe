// SPDX-License-Identifier: MIT
// Based on Avalanche's Maybe implementation
// Copyright (C) 2019-2024, Ava Labs, Inc. All rights reserved.
pragma solidity ^0.8.24;

/**
 * @title Maybe
 * @notice Type-safe optional value wrapper (Option/Maybe monad)
 * @dev Prevents null pointer errors and makes absence of value explicit
 *
 * Invariant: If hasValue is false, then value is the zero value of type T
 *
 * Based on Avalanche's Maybe[T] = Some T | Nothing pattern
 * See: https://en.wikipedia.org/wiki/Option_type
 */
library Maybe {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CORE TYPES                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    struct Bytes32 {
        bool hasValue;
        bytes32 value;
    }

    struct Uint256 {
        bool hasValue;
        uint256 value;
    }

    struct Address {
        bool hasValue;
        address value;
    }

    struct Bool {
        bool hasValue;
        bool value;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    CONSTRUCTOR FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Create a Maybe with a value (Some)
     */
    function some(bytes32 val) internal pure returns (Bytes32 memory) {
        return Bytes32({hasValue: true, value: val});
    }

    function some(uint256 val) internal pure returns (Uint256 memory) {
        return Uint256({hasValue: true, value: val});
    }

    function some(address val) internal pure returns (Address memory) {
        return Address({hasValue: true, value: val});
    }

    function some(bool val) internal pure returns (Bool memory) {
        return Bool({hasValue: true, value: val});
    }

    /**
     * @notice Create a Maybe with no value (Nothing)
     */
    function nothingBytes32() internal pure returns (Bytes32 memory) {
        return Bytes32({hasValue: false, value: bytes32(0)});
    }

    function nothingUint256() internal pure returns (Uint256 memory) {
        return Uint256({hasValue: false, value: 0});
    }

    function nothingAddress() internal pure returns (Address memory) {
        return Address({hasValue: false, value: address(0)});
    }

    function nothingBool() internal pure returns (Bool memory) {
        return Bool({hasValue: false, value: false});
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        QUERY FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Check if Maybe is Nothing
     */
    function isNothing(Bytes32 memory m) internal pure returns (bool) {
        return !m.hasValue;
    }

    function isNothing(Uint256 memory m) internal pure returns (bool) {
        return !m.hasValue;
    }

    function isNothing(Address memory m) internal pure returns (bool) {
        return !m.hasValue;
    }

    function isNothing(Bool memory m) internal pure returns (bool) {
        return !m.hasValue;
    }

    /**
     * @notice Get value (reverts if Nothing)
     */
    function value(Bytes32 memory m) internal pure returns (bytes32) {
        require(m.hasValue, "Maybe: value is Nothing");
        return m.value;
    }

    function value(Uint256 memory m) internal pure returns (uint256) {
        require(m.hasValue, "Maybe: value is Nothing");
        return m.value;
    }

    function value(Address memory m) internal pure returns (address) {
        require(m.hasValue, "Maybe: value is Nothing");
        return m.value;
    }

    function value(Bool memory m) internal pure returns (bool) {
        require(m.hasValue, "Maybe: value is Nothing");
        return m.value;
    }

    /**
     * @notice Get value or default
     */
    function valueOr(Bytes32 memory m, bytes32 defaultVal) internal pure returns (bytes32) {
        return m.hasValue ? m.value : defaultVal;
    }

    function valueOr(Uint256 memory m, uint256 defaultVal) internal pure returns (uint256) {
        return m.hasValue ? m.value : defaultVal;
    }

    function valueOr(Address memory m, address defaultVal) internal pure returns (address) {
        return m.hasValue ? m.value : defaultVal;
    }

    function valueOr(Bool memory m, bool defaultVal) internal pure returns (bool) {
        return m.hasValue ? m.value : defaultVal;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    FUNCTIONAL COMPOSITION                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Map function over Maybe value
     * @dev Returns Nothing if input is Nothing, else applies f and returns Some
     */
    function map(Uint256 memory m, function(uint256) internal pure returns (uint256) f)
        internal
        pure
        returns (Uint256 memory)
    {
        if (m.hasValue) {
            return some(f(m.value));
        }
        return nothingUint256();
    }

    /**
     * @notice Bind/FlatMap operation (monadic bind)
     * @dev Returns Nothing if input is Nothing, else applies f
     */
    function bind(Uint256 memory m, function(uint256) internal pure returns (Uint256 memory) f)
        internal
        pure
        returns (Uint256 memory)
    {
        if (m.hasValue) {
            return f(m.value);
        }
        return nothingUint256();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    CONVERSION UTILITIES                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Create Maybe from tuple (value, exists)
     * @dev Common pattern when migrating from (T, bool) returns
     */
    function fromTuple(bytes32 val, bool exists) internal pure returns (Bytes32 memory) {
        return exists ? some(val) : nothingBytes32();
    }

    function fromTuple(uint256 val, bool exists) internal pure returns (Uint256 memory) {
        return exists ? some(val) : nothingUint256();
    }

    function fromTuple(address val, bool exists) internal pure returns (Address memory) {
        return exists ? some(val) : nothingAddress();
    }

    function fromTuple(bool val, bool exists) internal pure returns (Bool memory) {
        return exists ? some(val) : nothingBool();
    }

    /**
     * @notice Convert Maybe to tuple (value, exists)
     */
    function toTuple(Bytes32 memory m) internal pure returns (bytes32, bool) {
        return (m.value, m.hasValue);
    }

    function toTuple(Uint256 memory m) internal pure returns (uint256, bool) {
        return (m.value, m.hasValue);
    }

    function toTuple(Address memory m) internal pure returns (address, bool) {
        return (m.value, m.hasValue);
    }

    function toTuple(Bool memory m) internal pure returns (bool, bool) {
        return (m.value, m.hasValue);
    }
}

/**
 * @title Result
 * @notice Extended Maybe with error information (Result<T, E> pattern)
 * @dev Used for operations that can fail with specific error reasons
 */
library Result {
    struct Uint256 {
        bool isSuccess;
        uint256 value;
        string errorMessage;
    }

    struct Address {
        bool isSuccess;
        address value;
        string errorMessage;
    }

    /**
     * @notice Create successful Result
     */
    function ok(uint256 val) internal pure returns (Uint256 memory) {
        return Uint256({isSuccess: true, value: val, errorMessage: ""});
    }

    function ok(address val) internal pure returns (Address memory) {
        return Address({isSuccess: true, value: val, errorMessage: ""});
    }

    /**
     * @notice Create error Result
     */
    function err(string memory message) internal pure returns (Uint256 memory) {
        return Uint256({isSuccess: false, value: 0, errorMessage: message});
    }

    function errAddress(string memory message) internal pure returns (Address memory) {
        return Address({isSuccess: false, value: address(0), errorMessage: message});
    }

    /**
     * @notice Unwrap Result (reverts on error)
     */
    function unwrap(Uint256 memory r) internal pure returns (uint256) {
        require(r.isSuccess, r.errorMessage);
        return r.value;
    }

    function unwrap(Address memory r) internal pure returns (address) {
        require(r.isSuccess, r.errorMessage);
        return r.value;
    }

    /**
     * @notice Unwrap or return default
     */
    function unwrapOr(Uint256 memory r, uint256 defaultVal) internal pure returns (uint256) {
        return r.isSuccess ? r.value : defaultVal;
    }

    function unwrapOr(Address memory r, address defaultVal) internal pure returns (address) {
        return r.isSuccess ? r.value : defaultVal;
    }
}
