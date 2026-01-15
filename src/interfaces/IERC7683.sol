// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ERC-7683: Cross-Chain Intents Standard
/// @notice Standard interface for cross-chain intent-based orders
/// @dev Enables invisible cross-chain UX where users sign intents on origin chain
/// and solvers fill them on destination chain(s)
/// @author EIP-7683 Authors (https://eips.ethereum.org/EIPS/eip-7683)

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                       CORE TYPES                           */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @notice Tokens sent by the swapper as inputs to the order
/// @param token The address of the ERC20 token on the origin chain
/// @param amount The amount of the token to be sent
struct Input {
    address token;
    uint256 amount;
}

/// @notice Tokens that must be received for a valid order fulfillment
/// @param token The address of the ERC20 token on the destination chain
///        (address(0) for native token)
/// @param amount The amount of the token to be received
/// @param recipient The address to receive the output tokens
/// @param chainId The destination chain for this output
struct Output {
    address token;
    uint256 amount;
    address recipient;
    uint256 chainId;
}

/// @notice Tokens that need to be sent on the destination chain
/// @param token The ERC20 token address on destination chain
/// @param amount The amount of tokens
/// @param recipient The recipient address
struct FillInstruction {
    uint64 destinationChainId;
    address destinationSettler;
    bytes originData;
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    GASLESS CROSS-CHAIN                     */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @notice A cross-chain order that does not require the swapper to pay gas
/// @dev The order can be sponsored by a relayer/solver
struct GaslessCrossChainOrder {
    /// @dev The contract address that the order is meant to be settled by
    address originSettler;
    /// @dev The address of the user who is swapping
    address user;
    /// @dev Nonce to prevent replay
    uint256 nonce;
    /// @dev The chainId of the origin chain
    uint256 originChainId;
    /// @dev The timestamp by which the order must be opened
    uint32 openDeadline;
    /// @dev The timestamp by which the order must be filled
    uint32 fillDeadline;
    /// @dev Type identifier for the order data
    bytes32 orderDataType;
    /// @dev Arbitrary order data (decoded by settler)
    bytes orderData;
}

/// @notice A standard cross-chain order (user pays origin gas)
struct OnchainCrossChainOrder {
    /// @dev The timestamp by which the order must be filled
    uint32 fillDeadline;
    /// @dev Type identifier for the order data
    bytes32 orderDataType;
    /// @dev Arbitrary order data
    bytes orderData;
}

/// @notice Resolved order with full details for execution
struct ResolvedCrossChainOrder {
    /// @dev The address of the user who is swapping
    address user;
    /// @dev The chainId of the origin chain
    uint256 originChainId;
    /// @dev The timestamp by which the order must be opened
    uint32 openDeadline;
    /// @dev The timestamp by which the order must be filled
    uint32 fillDeadline;
    /// @dev The inputs to be taken on the origin chain
    Input[] maxSpent;
    /// @dev The minimum outputs on the destination chain(s)
    Output[] minReceived;
    /// @dev Instructions for filling on destination chain(s)
    FillInstruction[] fillInstructions;
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                   ORIGIN SETTLER                           */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @title IOriginSettler
/// @notice Interface for the origin chain settler contract
interface IOriginSettler {
    /// @notice Emitted when an order is opened
    /// @param orderId Unique order identifier
    /// @param resolvedOrder The fully resolved order details
    event Open(bytes32 indexed orderId, ResolvedCrossChainOrder resolvedOrder);

    /// @notice Opens a gasless cross-chain order on behalf of a user
    /// @dev Must verify the user's signature
    /// @param order The gasless order signed by the user
    /// @param signature The user's signature over the order
    /// @param originFillerData Arbitrary data for the filler on origin chain
    function openFor(
        GaslessCrossChainOrder calldata order,
        bytes calldata signature,
        bytes calldata originFillerData
    ) external;

    /// @notice Opens a cross-chain order (user pays gas)
    /// @param order The order to open
    function open(OnchainCrossChainOrder calldata order) external;

    /// @notice Resolves a gasless order into a full ResolvedCrossChainOrder
    /// @param order The gasless order to resolve
    /// @param originFillerData Filler-specific data
    /// @return Fully resolved order
    function resolveFor(
        GaslessCrossChainOrder calldata order,
        bytes calldata originFillerData
    ) external view returns (ResolvedCrossChainOrder memory);

    /// @notice Resolves an onchain order
    /// @param order The order to resolve
    /// @return Fully resolved order
    function resolve(OnchainCrossChainOrder calldata order)
        external
        view
        returns (ResolvedCrossChainOrder memory);
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                 DESTINATION SETTLER                        */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @title IDestinationSettler
/// @notice Interface for the destination chain settler contract
interface IDestinationSettler {
    /// @notice Fills a cross-chain order on the destination chain
    /// @dev Called by solvers to fulfill user orders
    /// @param orderId Unique identifier for the order
    /// @param originData Data from the origin chain (contains order details)
    /// @param fillerData Solver-specific data for execution
    function fill(
        bytes32 orderId,
        bytes calldata originData,
        bytes calldata fillerData
    ) external;
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    ORDER DATA TYPES                        */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev Standard order data type for simple swaps
/// orderDataType = keccak256("SIMPLE_SWAP")
bytes32 constant SIMPLE_SWAP_TYPE = keccak256("SIMPLE_SWAP");

/// @dev Order data type for multi-hop swaps
/// orderDataType = keccak256("MULTI_HOP_SWAP")
bytes32 constant MULTI_HOP_SWAP_TYPE = keccak256("MULTI_HOP_SWAP");

/// @dev Order data type for flash loan arbitrage
/// orderDataType = keccak256("FLASH_ARB")
bytes32 constant FLASH_ARB_TYPE = keccak256("FLASH_ARB");

/// @notice Simple swap order data
struct SimpleSwapData {
    Input input;
    Output output;
}

/// @notice Multi-hop swap order data (for complex routes)
struct MultiHopSwapData {
    Input[] inputs;
    Output[] outputs;
    bytes routeData;  // Encoded routing instructions
}

/// @notice Flash arbitrage order data
struct FlashArbData {
    address flashProvider;
    uint256 flashAmount;
    Input[] inputs;
    Output[] outputs;
    bytes arbRouteData;
}
