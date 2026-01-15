// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7821} from "./IERC7821.sol";

/// @title IValidator: Modular Validator Interface for Smart Accounts
/// @notice Allows pluggable validation logic for account operations
/// @dev Validators can implement custom authorization schemes:
///      - Multi-sig validation
///      - Session keys with permissions
///      - Passkey/WebAuthn
///      - Social recovery
///      - Time-locked operations
///      - Spending limits
interface IValidator {
    /// @notice Validates a batch of calls with a signature
    /// @dev Called during UserOp validation or execute with opData
    /// @param calls The calls to be executed
    /// @param caller The address initiating the execution (EntryPoint or relayer)
    /// @param digest The hash to validate against (userOpHash or typed data hash)
    /// @param signature The signature data (format defined by validator)
    /// @return valid True if the signature is valid for this operation
    function validate(
        IERC7821.Call[] calldata calls,
        address caller,
        bytes32 digest,
        bytes calldata signature
    ) external returns (bool valid);

    /// @notice Called after successful execution
    /// @dev Use for cleanup, logging, or state updates
    ///      e.g., decrement spending allowance, update session usage
    function postExecute() external;

    /// @notice Validates a signature for ERC-1271 compatibility
    /// @param digest The hash that was signed
    /// @param signature The signature bytes
    /// @return magicValue 0x1626ba7e if valid, 0xffffffff otherwise
    function isValidSignature(bytes32 digest, bytes calldata signature)
        external
        view
        returns (bytes4 magicValue);
}
