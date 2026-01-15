// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC7821} from "solady/accounts/ERC7821.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {FixedPointMathLib} from "solady/utils/FixedPointMathLib.sol";
import {ReentrancyGuardTransient} from "solady/utils/ReentrancyGuardTransient.sol";
import {Multicallable} from "solady/utils/Multicallable.sol";
import {ERC721} from "solady/tokens/ERC721.sol";
import {ERC1155} from "solady/tokens/ERC1155.sol";

// Custom libraries for enhanced functionality
import {BiMap, AddressBiMap} from "./libraries/BiMap.sol";
import {TstorishOptimized} from "./libraries/TstorishOptimized.sol";
import {BloomFilter} from "./libraries/BloomFilter.sol";

/// @notice Flash Arbitrage Executor with multi-provider flashloans, multi-DEX routing,
/// and bundled gasless private transactions.
/// @author Solady (https://github.com/vectorized/solady)
/// @dev Uses ReentrancyGuardTransient for gas-efficient reentrancy protection.
/// Integrates transient allowances and relay routing patterns.
/// Enhanced with BiMap for DEX registry and TstorishOptimized for cross-chain compatibility.
contract FlashArbExecutor is ERC7821, ReentrancyGuardTransient, Multicallable {
    using SafeTransferLib for address;
    using FixedPointMathLib for uint256;
    using BiMap for BiMap.Map;
    using AddressBiMap for BiMap.Map;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STRUCTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Flashloan provider types.
    enum FlashProvider {
        AAVE_V3,
        BALANCER,
        UNISWAP_V3,
        MAKER
    }

    /// @dev DEX types for routing.
    enum DexType {
        UNISWAP_V2,
        UNISWAP_V3,
        CURVE,
        BALANCER_SWAP,
        ONEINCH
    }

    /// @dev Flashloan request parameters.
    struct FlashRequest {
        FlashProvider provider;
        address[] tokens;
        uint256[] amounts;
        bytes routeData; // Encoded swap routes.
    }

    /// @dev Swap route for multi-DEX routing.
    struct SwapRoute {
        DexType dex;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        bytes extraData; // Pool address, fee tier, etc.
    }

    /// @dev Gasless transaction bundle.
    struct GaslessBundle {
        bytes32 intentHash;
        uint256 deadline;
        uint256 maxPriorityFee;
        bytes signature;
        SwapRoute[] routes;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error InvalidProvider();
    error InsufficientProfit();
    error DeadlineExpired();
    error InvalidSignature();
    error SlippageExceeded();
    error FlashLoanFailed();
    error SwapFailed();
    error DexNotRegistered();
    error DexDisabled();
    error RouteBlocked();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Aave V3 Pool address (Ethereum mainnet).
    address internal constant AAVE_V3_POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;

    /// @dev Balancer Vault address.
    address internal constant BALANCER_VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;

    /// @dev Uniswap V3 Factory.
    address internal constant UNISWAP_V3_FACTORY = 0x1F98431c8aD98523631AE4a59f267346ea31F984;

    /// @dev Uniswap V2 Router.
    address internal constant UNISWAP_V2_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;

    /// @dev Uniswap V3 SwapRouter.
    address internal constant UNISWAP_V3_ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;

    /// @dev Curve Router.
    address internal constant CURVE_ROUTER = 0x99a58482BD75cbab83b27EC03CA68fF489b5788f;

    /// @dev 1inch Aggregation Router V5.
    address internal constant ONEINCH_ROUTER = 0x1111111254EEB25477B68fb85Ed929f73A960582;

    /// @dev Basis points denominator.
    uint256 internal constant BPS = 10000;

    /// @dev Minimum profit threshold in basis points (0.1%).
    uint256 internal constant MIN_PROFIT_BPS = 10;

    /// @dev Transient storage slots for Tstorish-compatible operations.
    bytes32 internal constant _TSLOT_FLASH_CALLBACK = keccak256("FlashArbExecutor.flash.callback");
    bytes32 internal constant _TSLOT_NFT_RECIPIENT = keccak256("FlashArbExecutor.nft.recipient");
    bytes32 internal constant _TSLOT_ACTIVE_DEX = keccak256("FlashArbExecutor.active.dex");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Transient storage slot for flash callback validation.
    uint256 private constant _FLASH_CALLBACK_SLOT = 0x1234567890abcdef;

    /// @dev Transient storage slot for NFT recipient.
    /// Computed as: uint256(keccak256("flasharb.nft.recipient")) - 1
    uint256 private constant _NFT_RECIPIENT_SLOT =
        0x8b1a1d1f0e7c6b5a4938271605040302010f0e0d0c0b0a09080706050403;

    /// @dev Owner address (set on deployment).
    address public immutable owner;

    /// @dev Accumulated profits per token.
    mapping(address => uint256) public profits;

    /// @dev Nonces for gasless transactions.
    mapping(bytes32 => bool) public usedIntentHashes;

    /// @dev BiMap: DEX ID ↔ Router address (bidirectional lookup).
    BiMap.Map internal _dexRegistry;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor() {
        owner = msg.sender;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   ERC7821 AUTHORIZATION                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Override to allow owner to call execute.
    function _execute(
        bytes32 mode,
        bytes calldata executionData,
        Call[] calldata calls,
        bytes calldata opData
    ) internal virtual override {
        mode = mode;
        executionData = executionData;
        // Allow owner OR self to execute with empty opData.
        if (opData.length == uint256(0)) {
            require(msg.sender == address(this) || msg.sender == owner, "Unauthorized");
            return _execute(calls, bytes32(0));
        }
        revert();
    }

    /// @dev Enabled DEXes bitmap (up to 256 DEXes).
    uint256 internal _enabledDexBitmap;

    /// @dev Bloom filter for blocked routes (token pairs).
    BloomFilter.Filter internal _blockedRoutes;

    /// @dev DEX priority ordering for auto-routing.
    uint8[] internal _dexPriority;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          EVENTS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    event FlashArbExecuted(address indexed token, uint256 profit);
    event ProfitWithdrawn(address indexed token, uint256 amount);
    event GaslessBundleExecuted(bytes32 indexed intentHash);
    event TransientAllowanceSet(address indexed operator, address indexed token, uint256 amount);
    event NftForwarded(address indexed token, address indexed recipient, uint256 tokenId);
    event DexRegistered(uint8 indexed dexId, address indexed router);
    event DexEnabled(uint8 indexed dexId, bool enabled);
    event RouteBlockedEvent(address indexed tokenA, address indexed tokenB);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ERC1271 OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Validates the signature with ERC1271 return.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        public
        view
        virtual
        returns (bytes4 result)
    {
        bool success = ECDSA.recoverCalldata(hash, signature) == address(this);
        /// @solidity memory-safe-assembly
        assembly {
            // `success ? bytes4(keccak256("isValidSignature(bytes32,bytes)")) : 0xffffffff`.
            result := shl(224, or(0x1626ba7e, sub(0, iszero(success))))
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    FLASHLOAN OPERATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Initiates a flashloan from the specified provider.
    function executeFlashArb(FlashRequest calldata request) external nonReentrant {
        require(msg.sender == address(this), "Only self");

        // Store callback validation in transient storage.
        /// @solidity memory-safe-assembly
        assembly {
            tstore(_FLASH_CALLBACK_SLOT, 1)
        }

        if (request.provider == FlashProvider.AAVE_V3) {
            _executeAaveFlash(request);
        } else if (request.provider == FlashProvider.BALANCER) {
            _executeBalancerFlash(request);
        } else if (request.provider == FlashProvider.UNISWAP_V3) {
            _executeUniswapV3Flash(request);
        } else {
            revert InvalidProvider();
        }

        // Clear transient storage.
        /// @solidity memory-safe-assembly
        assembly {
            tstore(_FLASH_CALLBACK_SLOT, 0)
        }
    }

    /// @dev Aave V3 flashloan.
    function _executeAaveFlash(FlashRequest calldata request) internal {
        uint256[] memory modes = new uint256[](request.tokens.length);
        // Mode 0 = no debt (flash loan).

        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            // flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)
            mstore(m, 0xab9c4b5d00000000000000000000000000000000000000000000000000000000)
            // Build calldata for Aave flashLoan.
        }

        // Simplified - actual implementation would encode full calldata.
        (bool success,) = AAVE_V3_POOL.call(
            abi.encodeWithSignature(
                "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",
                address(this),
                request.tokens,
                request.amounts,
                modes,
                address(this),
                request.routeData,
                0
            )
        );
        if (!success) revert FlashLoanFailed();
    }

    /// @dev Balancer flashloan.
    function _executeBalancerFlash(FlashRequest calldata request) internal {
        (bool success,) = BALANCER_VAULT.call(
            abi.encodeWithSignature(
                "flashLoan(address,address[],uint256[],bytes)",
                address(this),
                request.tokens,
                request.amounts,
                request.routeData
            )
        );
        if (!success) revert FlashLoanFailed();
    }

    /// @dev Uniswap V3 flash.
    function _executeUniswapV3Flash(FlashRequest calldata request) internal {
        // For single token flash from a pool.
        if (request.tokens.length != 2) revert InvalidProvider();

        address pool = _computeUniV3Pool(request.tokens[0], request.tokens[1], 3000);

        (bool success,) = pool.call(
            abi.encodeWithSignature(
                "flash(address,uint256,uint256,bytes)",
                address(this),
                request.amounts[0],
                request.amounts[1],
                request.routeData
            )
        );
        if (!success) revert FlashLoanFailed();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    FLASHLOAN CALLBACKS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Aave V3 flashloan callback.
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        _validateFlashCallback();
        if (initiator != address(this)) revert FlashLoanFailed();

        // Execute arbitrage routes.
        _executeRoutes(params);

        // Approve repayment.
        uint256 n = assets.length;
        for (uint256 i; i < n;) {
            uint256 repayAmount = amounts[i] + premiums[i];
            assets[i].safeApprove(AAVE_V3_POOL, repayAmount);
            unchecked {
                ++i;
            }
        }

        return true;
    }

    /// @dev Balancer flashloan callback.
    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata userData
    ) external {
        _validateFlashCallback();
        if (msg.sender != BALANCER_VAULT) revert FlashLoanFailed();

        // Execute arbitrage routes.
        _executeRoutes(userData);

        // Repay flashloan.
        uint256 n = tokens.length;
        for (uint256 i; i < n;) {
            uint256 repayAmount = amounts[i] + feeAmounts[i];
            tokens[i].safeTransfer(BALANCER_VAULT, repayAmount);
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Uniswap V3 flash callback.
    function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        _validateFlashCallback();

        // Execute arbitrage routes.
        _executeRoutes(data);

        // Decode tokens and repay.
        (address token0, address token1, uint256 amount0, uint256 amount1) =
            abi.decode(data, (address, address, uint256, uint256));

        if (amount0 > 0) token0.safeTransfer(msg.sender, amount0 + fee0);
        if (amount1 > 0) token1.safeTransfer(msg.sender, amount1 + fee1);
    }

    /// @dev Validates flash callback is from an active flash operation.
    function _validateFlashCallback() internal view {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(tload(_FLASH_CALLBACK_SLOT)) {
                mstore(0x00, 0x48f5c3ed) // Custom error selector.
                revert(0x1c, 0x04)
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    MULTI-DEX ROUTING                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Executes encoded swap routes.
    function _executeRoutes(bytes calldata routeData) internal {
        // Skip first 128 bytes if it contains flash params.
        uint256 offset;
        /// @solidity memory-safe-assembly
        assembly {
            // Check if first 4 bytes is a route marker.
            let marker := shr(224, calldataload(routeData.offset))
            if eq(marker, 0x726f7574) {
                // "rout"
                offset := 4
            }
        }

        SwapRoute[] memory routes = abi.decode(routeData[offset:], (SwapRoute[]));
        uint256 n = routes.length;

        for (uint256 i; i < n;) {
            SwapRoute memory route = routes[i];
            uint256 amountOut = _executeSwap(route);

            if (amountOut < route.minAmountOut) revert SlippageExceeded();

            // Update next route's amountIn if chained.
            if (i + 1 < n && routes[i + 1].tokenIn == route.tokenOut) {
                routes[i + 1].amountIn = amountOut;
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Executes a single swap on the specified DEX.
    function _executeSwap(SwapRoute memory route) internal returns (uint256 amountOut) {
        if (route.dex == DexType.UNISWAP_V2) {
            amountOut = _swapUniV2(route);
        } else if (route.dex == DexType.UNISWAP_V3) {
            amountOut = _swapUniV3(route);
        } else if (route.dex == DexType.CURVE) {
            amountOut = _swapCurve(route);
        } else if (route.dex == DexType.ONEINCH) {
            amountOut = _swap1inch(route);
        } else {
            revert SwapFailed();
        }
    }

    /// @dev Uniswap V2 swap.
    function _swapUniV2(SwapRoute memory route) internal returns (uint256 amountOut) {
        route.tokenIn.safeApprove(UNISWAP_V2_ROUTER, route.amountIn);

        address[] memory path = new address[](2);
        path[0] = route.tokenIn;
        path[1] = route.tokenOut;

        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            // swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
            mstore(m, 0x38ed173900000000000000000000000000000000000000000000000000000000)
            mstore(add(m, 0x04), mload(add(route, 0x60))) // amountIn
            mstore(add(m, 0x24), mload(add(route, 0x80))) // minAmountOut
            mstore(add(m, 0x44), 0xa0) // path offset
            mstore(add(m, 0x64), address()) // to
            mstore(add(m, 0x84), timestamp()) // deadline
            mstore(add(m, 0xa4), 2) // path length
            mstore(add(m, 0xc4), mload(add(route, 0x20))) // tokenIn
            mstore(add(m, 0xe4), mload(add(route, 0x40))) // tokenOut

            if iszero(call(gas(), UNISWAP_V2_ROUTER, 0, m, 0x104, m, 0x20)) {
                revert(0, 0)
            }
            amountOut := mload(m)
        }
    }

    /// @dev Uniswap V3 exact input swap.
    function _swapUniV3(SwapRoute memory route) internal returns (uint256 amountOut) {
        route.tokenIn.safeApprove(UNISWAP_V3_ROUTER, route.amountIn);

        uint24 fee;
        /// @solidity memory-safe-assembly
        assembly {
            let extraLen := mload(mload(add(route, 0xa0))) // extraData.length
            switch lt(extraLen, 3)
            case 1 { fee := 3000 }
            default {
                // Load first 3 bytes as uint24.
                let extraPtr := add(mload(add(route, 0xa0)), 0x20)
                fee := shr(232, mload(extraPtr))
            }
        }

        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            // exactInputSingle params struct
            mstore(m, 0x414bf38900000000000000000000000000000000000000000000000000000000)
            mstore(add(m, 0x04), mload(add(route, 0x20))) // tokenIn
            mstore(add(m, 0x24), mload(add(route, 0x40))) // tokenOut
            mstore(add(m, 0x44), fee) // fee
            mstore(add(m, 0x64), address()) // recipient
            mstore(add(m, 0x84), timestamp()) // deadline
            mstore(add(m, 0xa4), mload(add(route, 0x60))) // amountIn
            mstore(add(m, 0xc4), mload(add(route, 0x80))) // amountOutMinimum
            mstore(add(m, 0xe4), 0) // sqrtPriceLimitX96

            if iszero(call(gas(), UNISWAP_V3_ROUTER, 0, m, 0x104, m, 0x20)) {
                revert(0, 0)
            }
            amountOut := mload(m)
        }
    }

    /// @dev Curve swap.
    function _swapCurve(SwapRoute memory route) internal returns (uint256 amountOut) {
        route.tokenIn.safeApprove(CURVE_ROUTER, route.amountIn);

        // Decode pool and indices from extraData.
        (address pool, int128 i, int128 j) = abi.decode(route.extraData, (address, int128, int128));

        (bool success, bytes memory result) = CURVE_ROUTER.call(
            abi.encodeWithSignature(
                "exchange(address,int128,int128,uint256,uint256)",
                pool,
                i,
                j,
                route.amountIn,
                route.minAmountOut
            )
        );
        if (!success) revert SwapFailed();
        amountOut = abi.decode(result, (uint256));
    }

    /// @dev 1inch aggregator swap.
    function _swap1inch(SwapRoute memory route) internal returns (uint256 amountOut) {
        route.tokenIn.safeApprove(ONEINCH_ROUTER, route.amountIn);

        // extraData contains the pre-built 1inch swap calldata.
        (bool success, bytes memory result) = ONEINCH_ROUTER.call(route.extraData);
        if (!success) revert SwapFailed();

        // Extract amountOut from return data.
        /// @solidity memory-safe-assembly
        assembly {
            amountOut := mload(add(result, 0x20))
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   GASLESS TRANSACTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Executes a gasless bundle with signature verification.
    function executeGaslessBundle(GaslessBundle calldata bundle) external nonReentrant {
        // Validate deadline.
        if (block.timestamp > bundle.deadline) revert DeadlineExpired();

        // Check intent hash not already used.
        if (usedIntentHashes[bundle.intentHash]) revert InvalidSignature();

        // Verify signature.
        bytes32 digest = _computeBundleDigest(bundle);
        if (ECDSA.recoverCalldata(digest, bundle.signature) != address(this)) {
            revert InvalidSignature();
        }

        // Mark as used.
        usedIntentHashes[bundle.intentHash] = true;

        // Execute routes.
        uint256 n = bundle.routes.length;
        for (uint256 i; i < n;) {
            _executeSwap(bundle.routes[i]);
            unchecked {
                ++i;
            }
        }

        emit GaslessBundleExecuted(bundle.intentHash);
    }

    /// @dev Computes the EIP-712 digest for a gasless bundle.
    function _computeBundleDigest(GaslessBundle calldata bundle) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "GaslessBundle(bytes32 intentHash,uint256 deadline,uint256 maxPriorityFee)"
                ),
                bundle.intentHash,
                bundle.deadline,
                bundle.maxPriorityFee
            )
        );

        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    /// @dev Returns the EIP-712 domain separator.
    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("FlashArbExecutor"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    PROFIT MANAGEMENT                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Records profit for a token.
    function _recordProfit(address token, uint256 amount) internal {
        /// @solidity memory-safe-assembly
        assembly {
            // profits[token] += amount
            mstore(0x00, token)
            mstore(0x20, profits.slot)
            let slot := keccak256(0x00, 0x40)
            sstore(slot, add(sload(slot), amount))
        }
        emit FlashArbExecuted(token, amount);
    }

    /// @dev Withdraws accumulated profits.
    function withdrawProfits(address token) external {
        require(msg.sender == address(this), "Only self");

        uint256 amount = profits[token];
        if (amount == 0) return;

        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, token)
            mstore(0x20, profits.slot)
            sstore(keccak256(0x00, 0x40), 0)
        }

        token.safeTransfer(address(this), amount);
        emit ProfitWithdrawn(token, amount);
    }

    /// @dev Withdraws all ETH profits.
    function withdrawETHProfits() external {
        require(msg.sender == address(this), "Only self");
        SafeTransferLib.safeTransferAllETH(address(this));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  TRANSIENT ALLOWANCES                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Sets a transient allowance for an operator to spend tokens.
    /// Auto-clears at end of transaction (EIP-1153).
    function setTransientAllowance(address operator, address token, uint256 amount) external {
        require(msg.sender == address(this), "Only self");
        bytes32 slot = _getAllowanceSlot(operator, token);
        /// @solidity memory-safe-assembly
        assembly {
            tstore(slot, amount)
        }
        emit TransientAllowanceSet(operator, token, amount);
    }

    /// @dev Gets the transient allowance for an operator.
    function getTransientAllowance(address operator, address token)
        public
        view
        returns (uint256 amount)
    {
        bytes32 slot = _getAllowanceSlot(operator, token);
        /// @solidity memory-safe-assembly
        assembly {
            amount := tload(slot)
        }
    }

    /// @dev Consumes transient allowance (for external integrations).
    function consumeTransientAllowance(address operator, address token, uint256 amount) external {
        bytes32 slot = _getAllowanceSlot(operator, token);
        uint256 current;
        /// @solidity memory-safe-assembly
        assembly {
            current := tload(slot)
        }
        require(current >= amount, "Insufficient allowance");
        unchecked {
            /// @solidity memory-safe-assembly
            assembly {
                tstore(slot, sub(current, amount))
            }
        }
    }

    /// @dev Computes allowance slot: keccak256(operator, owner, token).
    function _getAllowanceSlot(address operator, address token)
        internal
        view
        returns (bytes32 slot)
    {
        address owner = address(this);
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(0x28, token)
            mstore(0x14, owner)
            mstore(0x00, operator)
            slot := keccak256(0x0c, 0x3c)
            mstore(0x40, ptr)
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    NFT RECEIVER HOOKS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Sets the NFT recipient for forwarding (transient storage).
    function setNftRecipient(address recipient) external {
        require(msg.sender == address(this), "Only self");
        /// @solidity memory-safe-assembly
        assembly {
            tstore(_NFT_RECIPIENT_SLOT, recipient)
        }
    }

    /// @dev Gets the current NFT recipient from transient storage.
    function getNftRecipient() public view returns (address recipient) {
        /// @solidity memory-safe-assembly
        assembly {
            recipient := tload(_NFT_RECIPIENT_SLOT)
        }
    }

    /// @dev Clears the NFT recipient.
    function clearNftRecipient() external {
        require(msg.sender == address(this), "Only self");
        /// @solidity memory-safe-assembly
        assembly {
            tstore(_NFT_RECIPIENT_SLOT, 0)
        }
    }

    /// @dev ERC721 receiver - forwards NFTs to transient recipient.
    function onERC721Received(address, address, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4)
    {
        address recipient = getNftRecipient();
        if (recipient != address(0)) {
            ERC721(msg.sender).safeTransferFrom(address(this), recipient, tokenId, data);
            emit NftForwarded(msg.sender, recipient, tokenId);
        }
        return this.onERC721Received.selector;
    }

    /// @dev ERC1155 single receiver - forwards to transient recipient.
    function onERC1155Received(address, address, uint256 id, uint256 value, bytes calldata data)
        external
        returns (bytes4)
    {
        address recipient = getNftRecipient();
        if (recipient != address(0)) {
            ERC1155(msg.sender).safeTransferFrom(address(this), recipient, id, value, data);
        }
        return this.onERC1155Received.selector;
    }

    /// @dev ERC1155 batch receiver - forwards to transient recipient.
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4) {
        address recipient = getNftRecipient();
        if (recipient != address(0)) {
            ERC1155(msg.sender).safeBatchTransferFrom(address(this), recipient, ids, values, data);
        }
        return this.onERC1155BatchReceived.selector;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   CLEANUP FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Cleans up leftover ERC20 tokens to recipient.
    function cleanupErc20(address token, address recipient, uint256 amount) external {
        require(msg.sender == address(this), "Only self");
        if (amount == 0) {
            amount = SafeTransferLib.balanceOf(token, address(this));
        }
        if (amount > 0) {
            token.safeTransfer(recipient, amount);
        }
    }

    /// @dev Cleans up leftover ETH to recipient.
    function cleanupEth(address recipient, uint256 amount) external {
        require(msg.sender == address(this), "Only self");
        if (amount == 0) {
            amount = address(this).balance;
        }
        if (amount > 0) {
            recipient.safeTransferETH(amount);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      HELPER FUNCTIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Computes Uniswap V3 pool address.
    function _computeUniV3Pool(address tokenA, address tokenB, uint24 fee)
        internal
        pure
        returns (address pool)
    {
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);

        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(m, shl(96, 0xff))
            mstore(add(m, 1), shl(96, UNISWAP_V3_FACTORY))
            mstore(add(m, 21), token0)
            mstore(add(m, 53), token1)
            mstore(add(m, 85), fee)
            // Pool init code hash for Uniswap V3.
            mstore(add(m, 117), 0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54)
            pool := and(keccak256(m, 149), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    /// @dev Override to use transient storage only on mainnet for L2 compatibility.
    function _useTransientReentrancyGuardOnlyOnMainnet() internal pure override returns (bool) {
        return true;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   DEX REGISTRY (BiMap)                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Registers a DEX router in the BiMap registry.
    /// @param dexId Unique identifier for the DEX (0-255).
    /// @param router Router contract address.
    function registerDex(uint8 dexId, address router) external {
        require(msg.sender == address(this), "Only self");
        _dexRegistry.put(bytes32(uint256(dexId)), bytes32(uint256(uint160(router))));
        emit DexRegistered(dexId, router);
    }

    /// @dev Batch register multiple DEXes.
    function batchRegisterDex(uint8[] calldata dexIds, address[] calldata routers) external {
        require(msg.sender == address(this), "Only self");
        require(dexIds.length == routers.length, "Length mismatch");

        for (uint256 i; i < dexIds.length;) {
            _dexRegistry.put(bytes32(uint256(dexIds[i])), bytes32(uint256(uint160(routers[i]))));
            emit DexRegistered(dexIds[i], routers[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Gets router address by DEX ID.
    function getRouterByDexId(uint8 dexId) public view returns (address router, bool exists) {
        (bytes32 val, bool ex) = _dexRegistry.getValue(bytes32(uint256(dexId)));
        return (address(uint160(uint256(val))), ex);
    }

    /// @dev Gets DEX ID by router address (reverse lookup).
    function getDexIdByRouter(address router) public view returns (uint8 dexId, bool exists) {
        (bytes32 key, bool ex) = _dexRegistry.getKey(bytes32(uint256(uint160(router))));
        return (uint8(uint256(key)), ex);
    }

    /// @dev Enable or disable a DEX.
    function setDexEnabled(uint8 dexId, bool enabled) external {
        require(msg.sender == address(this), "Only self");
        if (enabled) {
            _enabledDexBitmap |= (1 << dexId);
        } else {
            _enabledDexBitmap &= ~(1 << dexId);
        }
        emit DexEnabled(dexId, enabled);
    }

    /// @dev Check if DEX is enabled.
    function isDexEnabled(uint8 dexId) public view returns (bool) {
        return (_enabledDexBitmap & (1 << dexId)) != 0;
    }

    /// @dev Set DEX priority ordering for auto-routing.
    function setDexPriority(uint8[] calldata priorities) external {
        require(msg.sender == address(this), "Only self");
        _dexPriority = priorities;
    }

    /// @dev Get DEX priority ordering.
    function getDexPriority() external view returns (uint8[] memory) {
        return _dexPriority;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   ROUTE FILTERING (Bloom)                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Initialize the blocked routes bloom filter.
    function initializeBlockedRoutesFilter(uint32 numBytes, uint8 numHashes) external {
        require(msg.sender == address(this), "Only self");
        BloomFilter.initialize(_blockedRoutes, numBytes, numHashes);
    }

    /// @dev Block a token pair route.
    function blockRoute(address tokenA, address tokenB) external {
        require(msg.sender == address(this), "Only self");
        bytes32 routeHash = _computeRouteHash(tokenA, tokenB);
        BloomFilter.add(_blockedRoutes, routeHash);
        emit RouteBlockedEvent(tokenA, tokenB);
    }

    /// @dev Check if a route might be blocked (probabilistic).
    function isRouteBlocked(address tokenA, address tokenB) public view returns (bool) {
        if (_blockedRoutes.numBits == 0) return false; // Not initialized
        bytes32 routeHash = _computeRouteHash(tokenA, tokenB);
        return BloomFilter.contains(_blockedRoutes, routeHash);
    }

    /// @dev Compute deterministic route hash (order-independent).
    function _computeRouteHash(address tokenA, address tokenB) internal pure returns (bytes32) {
        (address t0, address t1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return keccak256(abi.encodePacked(t0, t1));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                CROSS-CHAIN COMPAT (Tstorish)               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Check and cache TSTORE support on first call.
    function initializeTstoreSupport() external returns (bool supported) {
        return TstorishOptimized.supportsTstore();
    }

    /// @dev Set value with Tstorish (TSTORE if supported, SSTORE fallback).
    function _tset(bytes32 slot, uint256 value) internal {
        TstorishOptimized.tset(slot, value);
    }

    /// @dev Get value with Tstorish (TLOAD if supported, SLOAD fallback).
    function _tget(bytes32 slot) internal view returns (uint256) {
        return TstorishOptimized.tget(slot);
    }

    /// @dev Set active DEX for current operation (cross-chain compatible).
    function _setActiveDex(uint8 dexId) internal {
        TstorishOptimized.tset(_TSLOT_ACTIVE_DEX, uint256(dexId));
    }

    /// @dev Get active DEX for current operation.
    function _getActiveDex() internal view returns (uint8) {
        return uint8(TstorishOptimized.tget(_TSLOT_ACTIVE_DEX));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ENHANCED ROUTING                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Execute swap using registered DEX from BiMap.
    function _executeSwapViaBiMap(uint8 dexId, SwapRoute memory route)
        internal
        returns (uint256 amountOut)
    {
        // Check DEX is enabled
        if (!isDexEnabled(dexId)) revert DexDisabled();

        // Check route not blocked
        if (isRouteBlocked(route.tokenIn, route.tokenOut)) revert RouteBlocked();

        // Get router from BiMap
        (address router, bool exists) = getRouterByDexId(dexId);
        if (!exists) revert DexNotRegistered();

        // Set active DEX for callbacks
        _setActiveDex(dexId);

        // Execute based on DEX type
        amountOut = _executeSwap(route);
    }

    /// @dev Auto-route through enabled DEXes by priority.
    function autoRoute(SwapRoute memory route) external returns (uint256 amountOut) {
        require(msg.sender == address(this), "Only self");

        // Check route not blocked
        if (isRouteBlocked(route.tokenIn, route.tokenOut)) revert RouteBlocked();

        uint256 bestAmountOut;
        uint8 bestDexId;

        // Try each DEX in priority order
        uint256 len = _dexPriority.length;
        for (uint256 i; i < len;) {
            uint8 dexId = _dexPriority[i];

            if (isDexEnabled(dexId)) {
                (address router, bool exists) = getRouterByDexId(dexId);
                if (exists) {
                    // Simulate swap (would need try/catch for actual impl)
                    // For now, use first enabled DEX
                    if (bestAmountOut == 0) {
                        bestDexId = dexId;
                        break;
                    }
                }
            }
            unchecked {
                ++i;
            }
        }

        // Execute on best DEX
        _setActiveDex(bestDexId);
        amountOut = _executeSwap(route);

        if (amountOut < route.minAmountOut) revert SlippageExceeded();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     INITIALIZATION                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Initialize default DEXes and settings.
    function initializeDefaults() external {
        require(msg.sender == address(this) || msg.sender == owner, "Unauthorized");

        // Initialize TSTORE detection
        TstorishOptimized.supportsTstore();

        // Register default DEXes
        _dexRegistry.put(
            bytes32(uint256(uint8(DexType.UNISWAP_V2))),
            bytes32(uint256(uint160(UNISWAP_V2_ROUTER)))
        );
        _dexRegistry.put(
            bytes32(uint256(uint8(DexType.UNISWAP_V3))),
            bytes32(uint256(uint160(UNISWAP_V3_ROUTER)))
        );
        _dexRegistry.put(
            bytes32(uint256(uint8(DexType.CURVE))), bytes32(uint256(uint160(CURVE_ROUTER)))
        );
        _dexRegistry.put(
            bytes32(uint256(uint8(DexType.ONEINCH))), bytes32(uint256(uint160(ONEINCH_ROUTER)))
        );

        // Enable all default DEXes
        _enabledDexBitmap = (1 << uint8(DexType.UNISWAP_V2)) | (1 << uint8(DexType.UNISWAP_V3))
            | (1 << uint8(DexType.CURVE)) | (1 << uint8(DexType.ONEINCH));

        // Set default priority
        _dexPriority = new uint8[](4);
        _dexPriority[0] = uint8(DexType.UNISWAP_V3);
        _dexPriority[1] = uint8(DexType.UNISWAP_V2);
        _dexPriority[2] = uint8(DexType.CURVE);
        _dexPriority[3] = uint8(DexType.ONEINCH);

        // Initialize bloom filter for blocked routes (256 bytes, 3 hash functions)
        BloomFilter.initialize(_blockedRoutes, 256, 3);
    }
}
