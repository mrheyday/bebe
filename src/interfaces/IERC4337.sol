// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ERC-4337: Account Abstraction Interface
/// @dev https://eips.ethereum.org/EIPS/eip-4337
/// @dev EntryPoint v0.8 compatible

/// @notice Packed user operation for v0.8 EntryPoint
/// @dev Uses packed gas limits for efficiency
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits; // packed: verificationGasLimit (16 bytes) | callGasLimit (16 bytes)
    uint256 preVerificationGas;
    bytes32 gasFees; // packed: maxPriorityFeePerGas (16 bytes) | maxFeePerGas (16 bytes)
    bytes paymasterAndData;
    bytes signature;
}

interface IERC4337 {
    /// @notice Validate user's signature and nonce
    /// @dev Must validate caller is the EntryPoint
    ///      Must validate the signature and nonce
    ///      Must pay any missing deposit to the EntryPoint
    /// @param userOp The operation that is about to be executed
    /// @param userOpHash Hash of the user's request data
    /// @param missingAccountFunds Missing funds on the account's deposit in the EntryPoint
    /// @return validationData Packed validation data:
    ///         - 0 = valid signature
    ///         - 1 = signature failure
    ///         - packed: (aggregator, validAfter, validUntil)
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);

    /// @notice Execute a user operation
    /// @dev Called by EntryPoint after validation
    /// @param userOp The user operation to execute
    /// @param userOpHash Hash of the user's request data
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external;

    /// @notice Get the account's entry point address
    /// @return The EntryPoint contract address
    function entryPoint() external view returns (address);
}
