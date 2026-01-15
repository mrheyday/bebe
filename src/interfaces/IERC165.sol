// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ERC-165: Standard Interface Detection
/// @dev https://eips.ethereum.org/EIPS/eip-165
interface IERC165 {
    /// @notice Query if a contract implements an interface
    /// @param interfaceID The interface identifier, as specified in ERC-165
    /// @return `true` if the contract implements `interfaceID` and
    ///         `interfaceID` is not 0xffffffff, `false` otherwise
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
}
