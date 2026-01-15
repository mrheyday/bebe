// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ERC-7821: Minimal Batch Executor Interface
/// @dev https://eips.ethereum.org/EIPS/eip-7821
/// @dev Based on ERC-7579 execution modes
interface IERC7821 {
    /// @notice A call to be executed
    /// @param to Target address (address(0) = self)
    /// @param value Native token value to send
    /// @param data Calldata to execute
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    /// @notice Executes a batch of calls
    /// @param mode The execution mode (callType, execType, modeSelector, modePayload)
    /// @param executionData The encoded calls and optional opData
    /// @dev Mode encoding (32 bytes):
    ///      - callType (1 byte): 0x00 = single, 0x01 = batch, 0xff = delegatecall
    ///      - execType (1 byte): 0x00 = revert on fail, 0x01 = try (return errors)
    ///      - unused (4 bytes)
    ///      - modeSelector (4 bytes): 0x00000000 = default, 0x78210001 = opData
    ///      - modePayload (22 bytes): additional context
    function execute(bytes32 mode, bytes calldata executionData) external payable;

    /// @notice Checks if an execution mode is supported
    /// @param mode The execution mode to check
    /// @return supported True if the mode is supported
    function supportsExecutionMode(bytes32 mode) external view returns (bool supported);
}
