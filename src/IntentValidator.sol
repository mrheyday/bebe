// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IValidator} from "./interfaces/IValidator.sol";
import {IERC7821} from "./interfaces/IERC7821.sol";
import {IERC1271} from "./interfaces/IERC1271.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {
    GaslessCrossChainOrder,
    IOriginSettler
} from "./interfaces/IERC7683.sol";

/// @title IntentValidator: Validator Module for Cross-Chain Intent Submission
/// @notice Enables Delegation accounts to submit gasless intents to CrossChainIntentSettler
/// @dev Validates that the calls are intent submissions with proper authorization
/// @author Flash6909 Team
contract IntentValidator is IValidator {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTANTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Function selectors for allowed operations
    bytes4 internal constant OPEN_SELECTOR = IOriginSettler.open.selector;
    bytes4 internal constant OPEN_FOR_SELECTOR = IOriginSettler.openFor.selector;
    bytes4 internal constant ERC20_APPROVE_SELECTOR = 0x095ea7b3;
    bytes4 internal constant ERC20_TRANSFER_SELECTOR = 0xa9059cbb;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice The CrossChainIntentSettler contract
    address public immutable settler;

    /// @notice Authorized signers for each delegation account
    /// @dev delegation account => signer => authorized
    mapping(address => mapping(address => bool)) public authorizedSigners;

    /// @notice Token spending limits per account per token
    /// @dev account => token => daily limit
    mapping(address => mapping(address => uint256)) public dailyLimits;

    /// @notice Token spending in current period
    /// @dev account => token => amount spent today
    mapping(address => mapping(address => uint256)) public dailySpent;

    /// @notice Period start timestamp
    /// @dev account => period start
    mapping(address => uint256) public periodStart;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          EVENTS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    event SignerAuthorized(address indexed account, address indexed signer, bool authorized);
    event DailyLimitSet(address indexed account, address indexed token, uint256 limit);
    event IntentSubmitted(address indexed account, bytes32 indexed orderId);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ERRORS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error UnauthorizedSigner();
    error InvalidTarget();
    error InvalidOperation();
    error DailyLimitExceeded();
    error InvalidSignature();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CONSTRUCTOR                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor(address _settler) {
        settler = _settler;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   IVALIDATOR INTERFACE                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IValidator
    function validate(
        IERC7821.Call[] calldata calls,
        address caller,
        bytes32 digest,
        bytes calldata signature
    ) external returns (bool) {
        // Extract signer from signature
        address signer = _recoverSigner(digest, signature);
        
        // Must be authorized signer for this account
        if (!authorizedSigners[msg.sender][signer]) {
            revert UnauthorizedSigner();
        }

        // Validate each call is allowed
        for (uint256 i = 0; i < calls.length; i++) {
            _validateCall(msg.sender, calls[i]);
        }

        return true;
    }

    /// @inheritdoc IValidator
    function postExecute() external {
        // Could emit events, update rate limits, etc.
        // Currently no-op
    }

    /// @inheritdoc IValidator
    function isValidSignature(bytes32 digest, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        address signer = _recoverSigner(digest, signature);
        
        if (authorizedSigners[msg.sender][signer]) {
            return bytes4(0x1626ba7e); // ERC-1271 magic value
        }
        
        return bytes4(0xffffffff);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   CONFIGURATION                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Authorize a signer for intent submission
    /// @dev Must be called by the delegation account itself
    /// @param signer The signer to authorize
    /// @param authorized Whether to authorize or revoke
    function authorizeSigner(address signer, bool authorized) external {
        authorizedSigners[msg.sender][signer] = authorized;
        emit SignerAuthorized(msg.sender, signer, authorized);
    }

    /// @notice Set daily spending limit for a token
    /// @dev Must be called by the delegation account itself
    /// @param token The token address
    /// @param limit The daily limit (0 = unlimited)
    function setDailyLimit(address token, uint256 limit) external {
        dailyLimits[msg.sender][token] = limit;
        emit DailyLimitSet(msg.sender, token, limit);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     INTERNAL HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Validate a single call is allowed
    function _validateCall(address account, IERC7821.Call calldata call) internal {
        bytes4 selector = bytes4(call.data[:4]);

        // Allow calls to settler for opening intents
        if (call.to == settler) {
            if (selector != OPEN_SELECTOR && selector != OPEN_FOR_SELECTOR) {
                revert InvalidOperation();
            }
            return;
        }

        // Allow ERC20 approvals to settler
        if (selector == ERC20_APPROVE_SELECTOR) {
            (address spender,) = abi.decode(call.data[4:], (address, uint256));
            if (spender != settler) {
                revert InvalidTarget();
            }
            return;
        }

        // Allow ERC20 transfers (for intent inputs) with limit checks
        if (selector == ERC20_TRANSFER_SELECTOR) {
            (, uint256 amount) = abi.decode(call.data[4:], (address, uint256));
            _checkDailyLimit(account, call.to, amount);
            return;
        }

        // All other operations are not allowed
        revert InvalidOperation();
    }

    /// @dev Check and update daily spending limit
    function _checkDailyLimit(address account, address token, uint256 amount) internal {
        uint256 limit = dailyLimits[account][token];
        if (limit == 0) return; // No limit set

        // Reset if new period
        if (block.timestamp >= periodStart[account] + 1 days) {
            periodStart[account] = block.timestamp;
            dailySpent[account][token] = 0;
        }

        uint256 newSpent = dailySpent[account][token] + amount;
        if (newSpent > limit) {
            revert DailyLimitExceeded();
        }

        dailySpent[account][token] = newSpent;
    }

    /// @dev Recover signer from signature
    function _recoverSigner(bytes32 digest, bytes calldata signature)
        internal
        pure
        returns (address)
    {
        if (signature.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // Reject malleable signatures
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignature();
        }

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();

        return signer;
    }
}
