// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title TransientAllowance
/// @notice Gas-efficient ephemeral allowances using EIP-1153 transient storage
/// @dev Based on 0x's AllowanceHolder with additional optimizations
library TransientAllowance {
    /// @notice Transient storage slot type
    type TSlot is bytes32;

    /// @notice Errors
    error InsufficientAllowance();
    error AllowanceExpired();

    /// @notice Get ephemeral allowance slot
    /// @dev Slot = keccak256(abi.encodePacked(operator, owner, token))
    function getAllowanceSlot(address operator, address owner, address token)
        internal
        pure
        returns (TSlot slot)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(0x28, token)
            mstore(0x14, owner)
            mstore(0x00, operator)
            slot := keccak256(0x0c, 0x3c)
            mstore(0x40, ptr) // Restore free pointer
        }
    }

    /// @notice Set transient allowance
    /// @param operator Address allowed to spend
    /// @param owner Token owner
    /// @param token Token address
    /// @param amount Allowance amount
    function setAllowance(address operator, address owner, address token, uint256 amount) internal {
        TSlot slot = getAllowanceSlot(operator, owner, token);
        /// @solidity memory-safe-assembly
        assembly {
            tstore(slot, amount)
        }
    }

    /// @notice Get transient allowance
    function getAllowance(address operator, address owner, address token)
        internal
        view
        returns (uint256 amount)
    {
        TSlot slot = getAllowanceSlot(operator, owner, token);
        /// @solidity memory-safe-assembly
        assembly {
            amount := tload(slot)
        }
    }

    /// @notice Consume transient allowance
    /// @dev Reverts if insufficient allowance
    function consumeAllowance(address operator, address owner, address token, uint256 amount)
        internal
    {
        TSlot slot = getAllowanceSlot(operator, owner, token);
        uint256 current;

        /// @solidity memory-safe-assembly
        assembly {
            current := tload(slot)
        }

        if (current < amount) revert InsufficientAllowance();

        unchecked {
            /// @solidity memory-safe-assembly
            assembly {
                tstore(slot, sub(current, amount))
            }
        }
    }

    /// @notice Clear transient allowance
    function clearAllowance(address operator, address owner, address token) internal {
        TSlot slot = getAllowanceSlot(operator, owner, token);
        /// @solidity memory-safe-assembly
        assembly {
            tstore(slot, 0)
        }
    }

    /// @notice Check if allowance is sufficient without consuming
    function hasAllowance(address operator, address owner, address token, uint256 amount)
        internal
        view
        returns (bool)
    {
        return getAllowance(operator, owner, token) >= amount;
    }
}
