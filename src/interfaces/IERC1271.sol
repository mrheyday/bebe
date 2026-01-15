// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ERC-1271: Standard Signature Validation Method for Contracts
/// @dev https://eips.ethereum.org/EIPS/eip-1271
interface IERC1271 {
    /// @notice Verifies that the signer is the owner of the signing contract
    /// @param hash Hash of the data to be signed
    /// @param signature Signature byte array associated with hash
    /// @return magicValue The bytes4 magic value 0x1626ba7e if valid
    /// @dev MUST return the bytes4 magic value 0x1626ba7e when function passes
    ///      MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc >= 0.5)
    ///      MUST allow external calls
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4 magicValue);
}
