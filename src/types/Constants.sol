// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    ERC-7579/7821 MODES                     */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev Call types for ERC-7579/7821 execution modes
bytes1 constant CALL_TYPE_SINGLE = 0x00;
bytes1 constant CALL_TYPE_BATCH = 0x01;
bytes1 constant CALL_TYPE_DELEGATECALL = 0xff;

/// @dev Execution types
bytes1 constant EXEC_TYPE_DEFAULT = 0x00; // Revert on failure
bytes1 constant EXEC_TYPE_TRY = 0x01;     // Continue on failure

/// @dev Mode selectors (bytes 6-9 of mode)
bytes4 constant EXEC_MODE_DEFAULT = 0x00000000;  // No opData
bytes4 constant EXEC_MODE_OP_DATA = 0x78210001;  // Has opData with signature

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    ENTRYPOINT ADDRESSES                    */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev ERC-4337 EntryPoint v0.8.0 (latest)
/// https://github.com/eth-infinitism/account-abstraction/releases/tag/v0.8.0
address constant ENTRY_POINT_V8 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;

/// @dev ERC-4337 EntryPoint v0.7.0
address constant ENTRY_POINT_V7 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

/// @dev ERC-4337 EntryPoint v0.6.0
address constant ENTRY_POINT_V6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                     SPECIAL ADDRESSES                      */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev Sentinel value for native token (ETH/MATIC/etc)
address constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

/// @dev Sentinel for address(0) representing self in Call.to
address constant SELF_ADDRESS = address(0);

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    GELATO RELAY ADDRESSES                  */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev Gelato Relay (same on all chains)
address constant GELATO_RELAY = 0xaBcC9b596420A9E9172FD5938620E265a0f9Df92;
address constant GELATO_RELAY_1BALANCE = 0x75bA5Af8EFFDCFca32E1e288806d54277D1fde99;
address constant GELATO_RELAY_CONCURRENT = 0x8598806401A63Ddf52473F1B3C55bC9E33e2d73b;
address constant GELATO_RELAY_1BALANCE_CONCURRENT = 0xc65d82EcE367f8DE8Ac7DcDFF91eFb9681C673F5;

/// @dev Gelato Trusted Forwarder (same on all chains)
address constant GELATO_TRUSTED_FORWARDER = 0xd8253782c45a12053594b9deB72d8e8aB2Fca54c;

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                        EIP-712 HASHES                      */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev keccak256("Execute(bytes32 mode,Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)")
bytes32 constant EXECUTE_TYPEHASH = 0xdf21343e200fb58137ad2784f9ea58605ec77f388015dc495486275b8eec47da;

/// @dev keccak256("Call(address to,uint256 value,bytes data)")
bytes32 constant CALL_TYPEHASH = 0x9085b19ea56248c94d86174b3784cfaaa8673d1041d6441f61ff52752dac8483;
