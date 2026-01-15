// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC165} from "./interfaces/IERC165.sol";
import {IERC7821} from "./interfaces/IERC7821.sol";
import {IERC1271} from "./interfaces/IERC1271.sol";
import {IERC4337, PackedUserOperation} from "./interfaces/IERC4337.sol";
import {IERC721TokenReceiver} from "./interfaces/IERC721TokenReceiver.sol";
import {IERC1155TokenReceiver} from "./interfaces/IERC1155TokenReceiver.sol";
import {IValidator} from "./interfaces/IValidator.sol";
import {
    CALL_TYPE_BATCH,
    EXEC_TYPE_DEFAULT,
    EXEC_MODE_DEFAULT,
    EXEC_MODE_OP_DATA,
    ENTRY_POINT_V8,
    EXECUTE_TYPEHASH,
    CALL_TYPEHASH
} from "./types/Constants.sol";
import {EIP712} from "solady/utils/EIP712.sol";

/// @title Delegation: ERC-4337 Smart Account with Modular Validators
/// @author Gelato Network
/// @notice A minimal, gas-efficient smart account supporting:
///         - ERC-4337 account abstraction (v0.8 EntryPoint)
///         - ERC-7821 batch execution with modes
///         - ERC-1271 signature validation
///         - Modular validator plugins for custom auth schemes
/// @dev Security considerations:
///      - Only self-calls allowed for direct execute() without opData
///      - Modular validators must be explicitly enabled
///      - Uses transient storage for validator context during UserOp
///      - Nonces use 192-bit key + 64-bit sequence for parallel ops
contract Delegation is
    IERC165,
    IERC7821,
    IERC1271,
    IERC4337,
    IERC721TokenReceiver,
    IERC1155TokenReceiver,
    EIP712
{
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ERRORS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error UnsupportedExecutionMode();
    error InvalidCaller();
    error InvalidValidator();
    error InvalidSignatureS();
    error InvalidSignature();
    error Unauthorized();
    error InvalidNonce();
    error ExcessiveInvalidation();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          EVENTS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    event ValidatorAdded(IValidator indexed validator);
    event ValidatorRemoved(IValidator indexed validator);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev ERC-7201 namespaced storage
    /// @custom:storage-location erc7201:gelato.delegation.storage
    struct Storage {
        mapping(uint192 key => uint64 seq) nonceSequenceNumber;
        mapping(IValidator => bool) validatorEnabled;
    }

    /// @dev keccak256(abi.encode(uint256(keccak256("gelato.delegation.storage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant STORAGE_LOCATION =
        0x1581abf533ae210f1ff5d25f322511179a9a65d8d8e43c998eab264f924af900;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         MODIFIERS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    modifier onlyThis() {
        if (msg.sender != address(this)) revert InvalidCaller();
        _;
    }

    modifier onlyEntryPoint() {
        if (msg.sender != entryPoint()) revert InvalidCaller();
        _;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       RECEIVE / FALLBACK                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    fallback() external payable {}
    receive() external payable {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    TOKEN RECEIVER HOOKS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external pure returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    ERC-7821 EXECUTION                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IERC7821
    function execute(bytes32 mode, bytes calldata executionData) external payable {
        _execute(mode, executionData, false);
    }

    /// @inheritdoc IERC7821
    function supportsExecutionMode(bytes32 mode) external pure returns (bool) {
        (bytes1 callType, bytes1 execType, bytes4 modeSelector,) = _decodeExecutionMode(mode);

        if (callType != CALL_TYPE_BATCH || execType != EXEC_TYPE_DEFAULT) {
            return false;
        }

        if (modeSelector != EXEC_MODE_DEFAULT && modeSelector != EXEC_MODE_OP_DATA) {
            return false;
        }

        return true;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       ERC-165                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return interfaceID == type(IERC165).interfaceId
            || interfaceID == this.onERC721Received.selector
            || interfaceID == this.onERC1155Received.selector ^ this.onERC1155BatchReceived.selector;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       ERC-1271                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 digest, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        // 65-byte signature = secp256k1 ECDSA
        if (signature.length == 65) {
            return _verifySignature(digest, signature) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
        }

        // Otherwise, delegate to validator module
        (IValidator validator, bytes calldata innerSignature) = _decodeValidator(signature);

        if (!_getStorage().validatorEnabled[validator]) {
            revert InvalidValidator();
        }

        return validator.isValidSignature(digest, innerSignature);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       ERC-4337                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IERC4337
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256) {
        // Pay prefund to EntryPoint
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (success); // Ignore - EntryPoint will verify
        }

        // 65-byte = secp256k1 ECDSA
        if (userOp.signature.length == 65) {
            return _verifySignature(userOpHash, userOp.signature) ? 0 : 1;
        }

        // Delegate to validator module
        (IValidator validator, bytes calldata innerSignature) = _decodeValidator(userOp.signature);

        if (!_getStorage().validatorEnabled[validator]) {
            revert InvalidValidator();
        }

        // Store validator in transient storage for postExecute
        _storeValidator(userOpHash, validator);

        Call[] calldata calls = _decodeCalls(userOp.callData[4:]);

        return validator.validate(calls, msg.sender, userOpHash, innerSignature) ? 0 : 1;
    }

    /// @inheritdoc IERC4337
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        onlyEntryPoint
    {
        Call[] calldata calls = _decodeCalls(userOp.callData[4:]);

        _executeCalls(calls);

        // Call postExecute on validator if one was used
        IValidator validator = _loadValidator(userOpHash);
        if (address(validator) != address(0)) {
            validator.postExecute();
        }
    }

    /// @inheritdoc IERC4337
    function entryPoint() public pure returns (address) {
        return ENTRY_POINT_V8;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   VALIDATOR MANAGEMENT                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Enable a validator module
    /// @param validator The validator to enable
    function addValidator(IValidator validator) external onlyThis {
        _getStorage().validatorEnabled[validator] = true;
        emit ValidatorAdded(validator);
    }

    /// @notice Disable a validator module
    /// @param validator The validator to disable
    function removeValidator(IValidator validator) external onlyThis {
        delete _getStorage().validatorEnabled[validator];
        emit ValidatorRemoved(validator);
    }

    /// @notice Check if a validator is enabled
    /// @param validator The validator to check
    /// @return True if enabled
    function isValidatorEnabled(IValidator validator) external view returns (bool) {
        return _getStorage().validatorEnabled[validator];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     NONCE MANAGEMENT                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Get the current nonce for a key
    /// @param key The 192-bit nonce key
    /// @return The full 256-bit nonce (key << 64 | seq)
    function getNonce(uint192 key) external view returns (uint256) {
        return _encodeNonce(key, _getStorage().nonceSequenceNumber[key]);
    }

    /// @notice Invalidate nonces up to a target value
    /// @dev Can skip at most 65535 nonces at once
    /// @param newNonce The new nonce value to set
    function invalidateNonce(uint256 newNonce) external onlyThis {
        (uint192 key, uint64 targetSeq) = _decodeNonce(newNonce);
        uint64 currentSeq = _getStorage().nonceSequenceNumber[key];

        if (targetSeq <= currentSeq) revert InvalidNonce();

        unchecked {
            uint64 delta = targetSeq - currentSeq;
            if (delta > type(uint16).max) revert ExcessiveInvalidation();
        }

        _getStorage().nonceSequenceNumber[key] = targetSeq;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    INTERNAL EXECUTION                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _execute(bytes32 mode, bytes calldata executionData, bool mockSignature) internal {
        (bytes1 callType, bytes1 execType, bytes4 modeSelector,) = _decodeExecutionMode(mode);

        if (callType != CALL_TYPE_BATCH || execType != EXEC_TYPE_DEFAULT) {
            revert UnsupportedExecutionMode();
        }

        Call[] calldata calls = _decodeCalls(executionData);

        if (modeSelector == EXEC_MODE_DEFAULT) {
            // No opData = must be self-call (ERC-7821 spec)
            if (msg.sender != address(this)) revert Unauthorized();
            _executeCalls(calls);
        } else if (modeSelector == EXEC_MODE_OP_DATA) {
            bytes calldata opData = _decodeOpData(executionData);
            bytes calldata signature = _decodeSignature(opData);

            uint256 nonce = _getAndUseNonce(_decodeNonceKey(opData));
            bytes32 digest = _computeDigest(mode, calls, nonce);

            if (signature.length == 65) {
                if (!_verifySignature(digest, signature) && !mockSignature) {
                    revert Unauthorized();
                }
                _executeCalls(calls);
            } else {
                (IValidator validator, bytes calldata innerSignature) = _decodeValidator(signature);

                if (!_getStorage().validatorEnabled[validator]) {
                    revert InvalidValidator();
                }

                if (!validator.validate(calls, msg.sender, digest, innerSignature) && !mockSignature) {
                    revert Unauthorized();
                }

                _executeCalls(calls);
                validator.postExecute();
            }
        } else {
            revert UnsupportedExecutionMode();
        }
    }

    function _executeCalls(Call[] calldata calls) internal {
        for (uint256 i = 0; i < calls.length; i++) {
            Call calldata c = calls[i];
            address to = c.to == address(0) ? address(this) : c.to;

            (bool success, bytes memory data) = to.call{value: c.value}(c.data);

            if (!success) {
                assembly {
                    revert(add(data, 32), mload(data))
                }
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    CALLDATA DECODING                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _decodeCalls(bytes calldata executionData)
        internal
        pure
        returns (Call[] calldata calls)
    {
        assembly {
            let offset := add(executionData.offset, calldataload(executionData.offset))
            calls.offset := add(offset, 32)
            calls.length := calldataload(offset)
        }
    }

    function _decodeOpData(bytes calldata executionData)
        internal
        pure
        returns (bytes calldata opData)
    {
        assembly {
            let offset := add(executionData.offset, calldataload(add(executionData.offset, 32)))
            opData.offset := add(offset, 32)
            opData.length := calldataload(offset)
        }
    }

    function _decodeNonceKey(bytes calldata opData) internal pure returns (uint192 nonceKey) {
        assembly {
            nonceKey := shr(64, calldataload(opData.offset))
        }
    }

    function _decodeSignature(bytes calldata opData)
        internal
        pure
        returns (bytes calldata signature)
    {
        assembly {
            signature.offset := add(opData.offset, 24)
            signature.length := sub(opData.length, 24)
        }
    }

    function _decodeSignatureComponents(bytes calldata signature)
        internal
        pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
    }

    function _decodeValidator(bytes calldata signature)
        internal
        pure
        returns (IValidator validator, bytes calldata data)
    {
        assembly {
            validator := shr(96, calldataload(signature.offset))
            data.offset := add(signature.offset, 20)
            data.length := sub(signature.length, 20)
        }
    }

    function _decodeExecutionMode(bytes32 mode)
        internal
        pure
        returns (bytes1 calltype, bytes1 execType, bytes4 modeSelector, bytes22 modePayload)
    {
        assembly {
            calltype := mode
            execType := shl(8, mode)
            modeSelector := shl(48, mode)
            modePayload := shl(80, mode)
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   SIGNATURE VERIFICATION                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _verifySignature(bytes32 digest, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        (bytes32 r, bytes32 s, uint8 v) = _decodeSignatureComponents(signature);

        // Reject malleable signatures
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignatureS();
        }

        address signer = ecrecover(digest, v, r, s);

        if (signer == address(0)) revert InvalidSignature();

        return signer == address(this);
    }

    function _computeDigest(bytes32 mode, Call[] calldata calls, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        bytes32[] memory callsHashes = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            callsHashes[i] = keccak256(
                abi.encode(CALL_TYPEHASH, calls[i].to, calls[i].value, keccak256(calls[i].data))
            );
        }

        bytes32 executeHash = keccak256(
            abi.encode(EXECUTE_TYPEHASH, mode, keccak256(abi.encodePacked(callsHashes)), nonce)
        );

        return _hashTypedData(executeHash);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      NONCE HELPERS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _getAndUseNonce(uint192 key) internal returns (uint256) {
        uint64 seq = _getStorage().nonceSequenceNumber[key];
        _getStorage().nonceSequenceNumber[key]++;
        return _encodeNonce(key, seq);
    }

    function _encodeNonce(uint192 key, uint64 seq) internal pure returns (uint256) {
        return (uint256(key) << 64) | seq;
    }

    function _decodeNonce(uint256 nonce) internal pure returns (uint192 key, uint64 seq) {
        key = uint192(nonce >> 64);
        seq = uint64(nonce);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     STORAGE HELPERS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _getStorage() internal pure returns (Storage storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }

    /// @dev Store validator in transient storage during UserOp execution
    function _storeValidator(bytes32 userOpHash, IValidator validator) internal {
        assembly {
            tstore(userOpHash, validator)
        }
    }

    /// @dev Load validator from transient storage
    function _loadValidator(bytes32 userOpHash) internal view returns (IValidator validator) {
        assembly {
            validator := tload(userOpHash)
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       EIP-712                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "GelatoDelegation";
        version = "0.0.1";
    }
}
