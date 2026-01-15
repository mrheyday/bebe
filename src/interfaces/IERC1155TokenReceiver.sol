// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ERC-1155 Token Receiver Interface
/// @dev https://eips.ethereum.org/EIPS/eip-1155
interface IERC1155TokenReceiver {
    /// @notice Handle the receipt of a single ERC1155 token type
    /// @dev An ERC1155-compliant smart contract MUST call this function on the token recipient contract
    /// @param operator The address which initiated the transfer
    /// @param from The address which previously owned the token
    /// @param id The ID of the token being transferred
    /// @param value The amount of tokens being transferred
    /// @param data Additional data with no specified format
    /// @return `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);

    /// @notice Handle the receipt of multiple ERC1155 token types
    /// @dev An ERC1155-compliant smart contract MUST call this function on the token recipient contract
    /// @param operator The address which initiated the batch transfer
    /// @param from The address which previously owned the token
    /// @param ids An array containing ids of each token being transferred
    /// @param values An array containing amounts of each token being transferred
    /// @param data Additional data with no specified format
    /// @return `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);
}
