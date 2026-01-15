// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC7821} from "solady/accounts/ERC7821.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {ReentrancyGuardTransient} from "solady/utils/ReentrancyGuardTransient.sol";
import {Multicallable} from "solady/utils/Multicallable.sol";
import {LibBitmap} from "solady/utils/LibBitmap.sol";

import {
    GaslessCrossChainOrder,
    OnchainCrossChainOrder,
    ResolvedCrossChainOrder,
    Input,
    Output,
    FillInstruction,
    IOriginSettler,
    IDestinationSettler,
    SIMPLE_SWAP_TYPE,
    MULTI_HOP_SWAP_TYPE,
    FLASH_ARB_TYPE,
    SimpleSwapData,
    MultiHopSwapData,
    FlashArbData
} from "./interfaces/IERC7683.sol";

/// @title CrossChainIntentSettler
/// @notice ERC-7683 compliant cross-chain intent settler for invisible UX
/// @dev Enables gasless cross-chain swaps with solver network
/// @author Flash6909 Team
contract CrossChainIntentSettler is 
    IOriginSettler, 
    IDestinationSettler, 
    ERC7821, 
    ReentrancyGuardTransient, 
    Multicallable 
{
    using SafeTransferLib for address;
    using LibBitmap for LibBitmap.Bitmap;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   GELATO RELAY ADDRESSES                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Gelato Relay addresses for onlyGelatoRelay modifier (same on all EVM chains)
    address internal constant GELATO_RELAY = 0xaBcC9b596420A9E9172FD5938620E265a0f9Df92;
    address internal constant GELATO_RELAY_1BALANCE = 0x75bA5Af8EFFDCFca32E1e288806d54277D1fde99;
    address internal constant GELATO_RELAY_CONCURRENT = 0x8598806401A63Ddf52473F1B3C55bC9E33e2d73b;
    address internal constant GELATO_RELAY_1BALANCE_CONCURRENT = 0xc65d82EcE367f8DE8Ac7DcDFF91eFb9681C673F5;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Owner of the settler
    address public owner;

    /// @notice Gelato-compatible trusted forwarder for meta-transactions (ERC-2771)
    address public trustedForwarder;

    /// @notice FlashArbExecutor for executing arb routes
    address public flashArbExecutor;

    /// @notice Trusted destination settlers on other chains
    mapping(uint256 chainId => address settler) public destinationSettlers;

    /// @notice Nonce tracking per user to prevent replay
    mapping(address user => uint256 nonce) public userNonces;

    /// @notice Opened orders pending fill
    mapping(bytes32 orderId => OrderState) public orders;

    /// @notice Registered fillers/solvers
    mapping(address => bool) public registeredFillers;

    /// @notice Bitmap for filled order tracking (gas efficient)
    LibBitmap.Bitmap internal _filledOrders;

    /// @notice Order state
    struct OrderState {
        bool isOpen;
        bool isFilled;
        address user;
        uint256 originChainId;
        uint32 fillDeadline;
        bytes32 orderHash;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         EVENTS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    event OrderFilled(
        bytes32 indexed orderId,
        address indexed filler,
        address indexed recipient,
        uint256 amountOut
    );

    event DestinationSettlerUpdated(uint256 indexed chainId, address settler);
    event FillerRegistered(address indexed filler, bool registered);
    event FlashArbExecutorUpdated(address indexed executor);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        ERRORS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error Unauthorized();
    error InvalidSignature();
    error InvalidNonce();
    error OrderExpired();
    error OrderAlreadyFilled();
    error OrderNotOpen();
    error InvalidOrderType();
    error InsufficientOutput();
    error InvalidDestinationChain();
    error FillerNotRegistered();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      MODIFIERS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier onlyRegisteredFiller() {
        if (!registeredFillers[msg.sender]) revert FillerNotRegistered();
        _;
    }

    /// @notice Modifier to restrict calls to Gelato Relay only
    /// @dev Critical security: validates msg.sender is an official Gelato Relay address
    modifier onlyGelatoRelay() {
        if (!_isGelatoRelay(msg.sender)) revert Unauthorized();
        _;
    }

    /// @notice Check if an address is a valid Gelato Relay
    function _isGelatoRelay(address _forwarder) internal pure returns (bool) {
        return _forwarder == GELATO_RELAY 
            || _forwarder == GELATO_RELAY_1BALANCE
            || _forwarder == GELATO_RELAY_CONCURRENT
            || _forwarder == GELATO_RELAY_1BALANCE_CONCURRENT;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     CONSTRUCTOR                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor(address _owner, address _flashArbExecutor, address _trustedForwarder) {
        owner = _owner;
        flashArbExecutor = _flashArbExecutor;
        trustedForwarder = _trustedForwarder;
        registeredFillers[_owner] = true;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   ERC-2771 CONTEXT                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    event TrustedForwarderUpdated(address indexed oldForwarder, address indexed newForwarder);

    /// @notice Check if an address is the trusted forwarder
    /// @param forwarder Address to check
    /// @return True if the address is the trusted forwarder
    function isTrustedForwarder(address forwarder) public view returns (bool) {
        return forwarder == trustedForwarder;
    }

    /// @notice Get the actual sender (ERC-2771 compliant)
    /// @dev Extracts sender from calldata when called via trusted forwarder or Gelato Relay
    /// @return sender The actual message sender
    function _msgSender() internal view returns (address sender) {
        // Check both trusted forwarder and official Gelato Relay addresses
        bool isForwarderCall = msg.sender == trustedForwarder || _isGelatoRelay(msg.sender);
        
        if (isForwarderCall && msg.data.length >= 20) {
            // Extract sender from last 20 bytes of calldata
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }

    /// @notice Get the actual calldata (ERC-2771 compliant)
    /// @dev Strips appended sender when called via trusted forwarder
    /// @return The actual calldata
    function _msgData() internal view returns (bytes calldata) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            return msg.data[:msg.data.length - 20];
        }
        return msg.data;
    }

    /// @notice Update the trusted forwarder (owner only)
    /// @param newForwarder New trusted forwarder address
    function setTrustedForwarder(address newForwarder) external onlyOwner {
        address oldForwarder = trustedForwarder;
        trustedForwarder = newForwarder;
        emit TrustedForwarderUpdated(oldForwarder, newForwarder);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   ORIGIN SETTLER                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IOriginSettler
    function openFor(
        GaslessCrossChainOrder calldata order,
        bytes calldata signature,
        bytes calldata originFillerData
    ) external override nonReentrant {
        // Verify deadline
        if (block.timestamp > order.openDeadline) revert OrderExpired();

        // Verify nonce
        if (order.nonce != userNonces[order.user]) revert InvalidNonce();

        // Verify signature using EIP-712
        bytes32 orderHash = _hashGaslessOrder(order);
        if (!SignatureCheckerLib.isValidSignatureNow(order.user, orderHash, signature)) {
            revert InvalidSignature();
        }

        // Increment nonce
        userNonces[order.user]++;

        // Generate order ID
        bytes32 orderId = keccak256(abi.encode(orderHash, block.chainid, block.timestamp));

        // Resolve the order
        ResolvedCrossChainOrder memory resolved = resolveFor(order, originFillerData);

        // Store order state
        orders[orderId] = OrderState({
            isOpen: true,
            isFilled: false,
            user: order.user,
            originChainId: order.originChainId,
            fillDeadline: order.fillDeadline,
            orderHash: orderHash
        });

        // Pull input tokens from user (using permit or pre-approval)
        for (uint256 i = 0; i < resolved.maxSpent.length; i++) {
            Input memory input = resolved.maxSpent[i];
            input.token.safeTransferFrom(order.user, address(this), input.amount);
        }

        emit Open(orderId, resolved);
    }

    /// @inheritdoc IOriginSettler
    /// @dev Supports ERC-2771 meta-transactions via Gelato trusted forwarder
    function open(OnchainCrossChainOrder calldata order) external override nonReentrant {
        // Verify deadline
        if (block.timestamp > order.fillDeadline) revert OrderExpired();

        // Get actual sender (supports Gelato meta-transactions)
        address sender = _msgSender();

        // Generate order ID from caller + timestamp
        bytes32 orderId = keccak256(abi.encode(sender, order.orderDataType, block.timestamp));

        // Resolve the order
        ResolvedCrossChainOrder memory resolved = resolve(order);

        // Store order state
        orders[orderId] = OrderState({
            isOpen: true,
            isFilled: false,
            user: sender,
            originChainId: block.chainid,
            fillDeadline: order.fillDeadline,
            orderHash: keccak256(order.orderData)
        });

        // Pull input tokens from user
        for (uint256 i = 0; i < resolved.maxSpent.length; i++) {
            Input memory input = resolved.maxSpent[i];
            input.token.safeTransferFrom(sender, address(this), input.amount);
        }

        emit Open(orderId, resolved);
    }

    /// @inheritdoc IOriginSettler
    function resolveFor(
        GaslessCrossChainOrder calldata order,
        bytes calldata /* originFillerData */
    ) public view override returns (ResolvedCrossChainOrder memory resolved) {
        resolved.user = order.user;
        resolved.originChainId = order.originChainId;
        resolved.openDeadline = order.openDeadline;
        resolved.fillDeadline = order.fillDeadline;

        // Decode based on order type
        if (order.orderDataType == SIMPLE_SWAP_TYPE) {
            SimpleSwapData memory data = abi.decode(order.orderData, (SimpleSwapData));
            
            resolved.maxSpent = new Input[](1);
            resolved.maxSpent[0] = data.input;
            
            resolved.minReceived = new Output[](1);
            resolved.minReceived[0] = data.output;
            
            resolved.fillInstructions = new FillInstruction[](1);
            resolved.fillInstructions[0] = FillInstruction({
                destinationChainId: uint64(data.output.chainId),
                destinationSettler: destinationSettlers[data.output.chainId],
                originData: order.orderData
            });
        } else if (order.orderDataType == MULTI_HOP_SWAP_TYPE) {
            MultiHopSwapData memory data = abi.decode(order.orderData, (MultiHopSwapData));
            
            resolved.maxSpent = data.inputs;
            resolved.minReceived = data.outputs;
            
            // Create fill instructions for each unique destination chain
            uint256 uniqueChains = _countUniqueChains(data.outputs);
            resolved.fillInstructions = new FillInstruction[](uniqueChains);
            
            uint256 idx;
            uint256 lastChain;
            for (uint256 i = 0; i < data.outputs.length; i++) {
                if (data.outputs[i].chainId != lastChain) {
                    resolved.fillInstructions[idx] = FillInstruction({
                        destinationChainId: uint64(data.outputs[i].chainId),
                        destinationSettler: destinationSettlers[data.outputs[i].chainId],
                        originData: order.orderData
                    });
                    lastChain = data.outputs[i].chainId;
                    idx++;
                }
            }
        } else if (order.orderDataType == FLASH_ARB_TYPE) {
            FlashArbData memory data = abi.decode(order.orderData, (FlashArbData));
            
            resolved.maxSpent = data.inputs;
            resolved.minReceived = data.outputs;
            
            resolved.fillInstructions = new FillInstruction[](1);
            resolved.fillInstructions[0] = FillInstruction({
                destinationChainId: uint64(block.chainid),
                destinationSettler: address(this),
                originData: order.orderData
            });
        } else {
            revert InvalidOrderType();
        }
    }

    /// @inheritdoc IOriginSettler
    function resolve(OnchainCrossChainOrder calldata order)
        public
        view
        override
        returns (ResolvedCrossChainOrder memory resolved)
    {
        resolved.user = msg.sender;
        resolved.originChainId = block.chainid;
        resolved.openDeadline = uint32(block.timestamp);
        resolved.fillDeadline = order.fillDeadline;

        // Same decoding logic as resolveFor
        if (order.orderDataType == SIMPLE_SWAP_TYPE) {
            SimpleSwapData memory data = abi.decode(order.orderData, (SimpleSwapData));
            
            resolved.maxSpent = new Input[](1);
            resolved.maxSpent[0] = data.input;
            
            resolved.minReceived = new Output[](1);
            resolved.minReceived[0] = data.output;
            
            resolved.fillInstructions = new FillInstruction[](1);
            resolved.fillInstructions[0] = FillInstruction({
                destinationChainId: uint64(data.output.chainId),
                destinationSettler: destinationSettlers[data.output.chainId],
                originData: order.orderData
            });
        } else {
            revert InvalidOrderType();
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                DESTINATION SETTLER                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IDestinationSettler
    function fill(
        bytes32 orderId,
        bytes calldata originData,
        bytes calldata fillerData
    ) external override nonReentrant onlyRegisteredFiller {
        // Decode the order type from originData
        (bytes32 orderDataType, bytes memory orderData) = abi.decode(originData, (bytes32, bytes));

        if (orderDataType == SIMPLE_SWAP_TYPE) {
            _fillSimpleSwap(orderId, orderData, fillerData);
        } else if (orderDataType == MULTI_HOP_SWAP_TYPE) {
            _fillMultiHop(orderId, orderData, fillerData);
        } else if (orderDataType == FLASH_ARB_TYPE) {
            _fillFlashArb(orderId, orderData, fillerData);
        } else {
            revert InvalidOrderType();
        }
    }

    /// @notice Fill a simple swap order
    function _fillSimpleSwap(
        bytes32 orderId,
        bytes memory orderData,
        bytes calldata /* fillerData */
    ) internal {
        SimpleSwapData memory data = abi.decode(orderData, (SimpleSwapData));
        
        // Transfer output tokens to recipient
        data.output.token.safeTransferFrom(
            msg.sender,
            data.output.recipient,
            data.output.amount
        );

        emit OrderFilled(orderId, msg.sender, data.output.recipient, data.output.amount);
    }

    /// @notice Fill a multi-hop swap order
    function _fillMultiHop(
        bytes32 orderId,
        bytes memory orderData,
        bytes calldata /* fillerData */
    ) internal {
        MultiHopSwapData memory data = abi.decode(orderData, (MultiHopSwapData));

        // Transfer all outputs to their recipients
        for (uint256 i = 0; i < data.outputs.length; i++) {
            Output memory output = data.outputs[i];
            if (output.chainId == block.chainid) {
                output.token.safeTransferFrom(msg.sender, output.recipient, output.amount);
                emit OrderFilled(orderId, msg.sender, output.recipient, output.amount);
            }
        }
    }

    /// @notice Fill a flash arbitrage order (uses FlashArbExecutor)
    function _fillFlashArb(
        bytes32 orderId,
        bytes memory orderData,
        bytes calldata fillerData
    ) internal {
        FlashArbData memory data = abi.decode(orderData, (FlashArbData));

        // Execute flash arb through executor
        (bool success,) = flashArbExecutor.call(fillerData);
        if (!success) revert();

        // Transfer outputs
        for (uint256 i = 0; i < data.outputs.length; i++) {
            Output memory output = data.outputs[i];
            if (output.chainId == block.chainid) {
                output.token.safeTransfer(output.recipient, output.amount);
                emit OrderFilled(orderId, msg.sender, output.recipient, output.amount);
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    HELPER FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Hash a gasless order for signature verification
    function _hashGaslessOrder(GaslessCrossChainOrder calldata order) 
        internal 
        pure 
        returns (bytes32) 
    {
        return keccak256(abi.encode(
            keccak256("GaslessCrossChainOrder(address originSettler,address user,uint256 nonce,uint256 originChainId,uint32 openDeadline,uint32 fillDeadline,bytes32 orderDataType,bytes orderData)"),
            order.originSettler,
            order.user,
            order.nonce,
            order.originChainId,
            order.openDeadline,
            order.fillDeadline,
            order.orderDataType,
            keccak256(order.orderData)
        ));
    }

    /// @notice Count unique chains in outputs
    function _countUniqueChains(Output[] memory outputs) internal pure returns (uint256 count) {
        if (outputs.length == 0) return 0;
        count = 1;
        for (uint256 i = 1; i < outputs.length; i++) {
            bool unique = true;
            for (uint256 j = 0; j < i; j++) {
                if (outputs[i].chainId == outputs[j].chainId) {
                    unique = false;
                    break;
                }
            }
            if (unique) count++;
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ADMIN                                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Set destination settler for a chain
    function setDestinationSettler(uint256 chainId, address settler) external onlyOwner {
        destinationSettlers[chainId] = settler;
        emit DestinationSettlerUpdated(chainId, settler);
    }

    /// @notice Register/unregister a filler
    function setFillerRegistration(address filler, bool registered) external onlyOwner {
        registeredFillers[filler] = registered;
        emit FillerRegistered(filler, registered);
    }

    /// @notice Update flash arb executor
    function setFlashArbExecutor(address executor) external onlyOwner {
        flashArbExecutor = executor;
        emit FlashArbExecutorUpdated(executor);
    }

    /// @notice Transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ERC7821 OVERRIDE                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Only owner can execute
    function _authorizedExecutor(Call[] calldata, bytes calldata)
        internal
        view
        virtual
        returns (address)
    {
        return owner;
    }

    /// @notice Receive ETH
    receive() external payable override {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              SECURE MULTICALL OVERRIDE                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Safe multicall that preserves ERC-2771 context
    /// @dev Prevents the ERC-2771 + delegatecall vulnerability by appending context
    /// @dev See: https://blog.openzeppelin.com/arbitrary-address-spoofing-vulnerability-erc2771context-multicall-public-disclosure
    /// @param data Array of encoded function calls
    /// @return results Array of return data from each call
    function multicall(bytes[] calldata data) public payable override returns (bytes[] memory results) {
        // SECURITY: Prevent ERC-2771 + delegatecall vulnerability
        // See: https://blog.openzeppelin.com/arbitrary-address-spoofing-vulnerability-erc2771context-multicall-public-disclosure
        //
        // When called via Gelato Relay or trusted forwarder, the original sender address
        // is appended to calldata. We must preserve this context for each delegatecall.
        
        // Determine if we're being called by a Gelato Relay or trusted forwarder
        bool isForwarderCall = msg.sender == trustedForwarder || _isGelatoRelay(msg.sender);
        
        // Extract context (last 20 bytes = original sender) if applicable
        bytes memory context;
        if (isForwarderCall && msg.data.length >= 20) {
            context = msg.data[msg.data.length - 20:];
        }
        
        results = new bytes[](data.length);
        
        for (uint256 i = 0; i < data.length; i++) {
            // Append context to preserve original sender for each delegatecall
            bytes memory callData = context.length > 0 
                ? bytes.concat(data[i], context) 
                : data[i];
            
            (bool success, bytes memory result) = address(this).delegatecall(callData);
            
            if (!success) {
                // Bubble up the revert reason
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
            
            results[i] = result;
        }
    }
}
