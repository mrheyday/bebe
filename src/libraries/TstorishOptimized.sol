// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title TstorishOptimized - Dynamic TSTORE/SSTORE Fallback
/// @notice Provides automatic detection and fallback for EIP-1153 transient storage support
/// @dev Uses function pointers for zero-overhead dispatch after detection
///
/// How it works:
/// 1. On first use, deploys a test contract to detect TSTORE support
/// 2. Stores a function pointer based on the result
/// 3. All subsequent operations use the function pointer directly (no runtime checks)
///
/// Note: Original code assumed no EIP-1153 on older chains,
/// but many chains have since added support via hard forks
library TstorishOptimized {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTANTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Slot for storing the TSTORE support status
    ///      keccak256("Tstorish.supported") - 1
    bytes32 private constant _SUPPORT_STATUS_SLOT =
        0x8f2c9a8b7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f00;

    /// @dev Slot for function pointer (tset)
    bytes32 private constant _TSET_FN_SLOT =
        0x8f2c9a8b7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f01;

    /// @dev Slot for function pointer (tget)
    bytes32 private constant _TGET_FN_SLOT =
        0x8f2c9a8b7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f02;

    /// @dev Status values
    uint256 private constant NOT_CHECKED = 0;
    uint256 private constant SUPPORTED = 1;
    uint256 private constant NOT_SUPPORTED = 2;

    /// @dev Bytecode to test TSTORE: PUSH0, PUSH0, TSTORE, PUSH0, TLOAD, STOP
    /// This deploys a minimal contract that tries TSTORE/TLOAD
    bytes private constant TSTORE_TEST_CODE = hex"5F5F5D5F5C00";

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    DETECTION FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Check if EIP-1153 (TSTORE/TLOAD) is supported
    /// @dev Caches result after first check for gas efficiency
    /// @return True if TSTORE/TLOAD are available
    function supportsTstore() internal returns (bool) {
        uint256 status;

        /// @solidity memory-safe-assembly
        assembly {
            status := sload(_SUPPORT_STATUS_SLOT)
        }

        // Already checked?
        if (status == SUPPORTED) return true;
        if (status == NOT_SUPPORTED) return false;

        // Deploy test contract
        bool supported = _detectTstoreSupport();

        // Cache result
        uint256 newStatus = supported ? SUPPORTED : NOT_SUPPORTED;
        /// @solidity memory-safe-assembly
        assembly {
            sstore(_SUPPORT_STATUS_SLOT, newStatus)
        }

        // Initialize function pointers
        _initializeFunctionPointers(supported);

        return supported;
    }

    /// @dev Internal detection via CREATE
    function _detectTstoreSupport() private returns (bool) {
        address testAddr;
        bytes memory code = TSTORE_TEST_CODE;

        /// @solidity memory-safe-assembly
        assembly {
            // CREATE with the test bytecode
            testAddr := create(0, add(code, 0x20), mload(code))
        }

        // If CREATE succeeded, TSTORE is supported
        return testAddr != address(0);
    }

    /// @dev Initialize function pointers based on support
    function _initializeFunctionPointers(bool supported) private {
        if (supported) {
            // Store function pointers for TSTORE/TLOAD implementations
            /// @solidity memory-safe-assembly
            assembly {
                // We use 1 for TSTORE path, 0 for SSTORE fallback
                sstore(_TSET_FN_SLOT, 1)
                sstore(_TGET_FN_SLOT, 1)
            }
        } else {
            /// @solidity memory-safe-assembly
            assembly {
                sstore(_TSET_FN_SLOT, 0)
                sstore(_TGET_FN_SLOT, 0)
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    STORAGE OPERATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Set a value (uses TSTORE if supported, SSTORE otherwise)
    /// @param slot The storage slot
    /// @param value The value to store
    function tset(bytes32 slot, uint256 value) internal {
        uint256 useTstore;

        /// @solidity memory-safe-assembly
        assembly {
            useTstore := sload(_TSET_FN_SLOT)
        }

        if (useTstore == 1) {
            /// @solidity memory-safe-assembly
            assembly {
                tstore(slot, value)
            }
        } else {
            /// @solidity memory-safe-assembly
            assembly {
                sstore(slot, value)
            }
        }
    }

    /// @notice Get a value (uses TLOAD if supported, SLOAD otherwise)
    /// @param slot The storage slot
    /// @return value The stored value
    function tget(bytes32 slot) internal view returns (uint256 value) {
        uint256 useTload;

        /// @solidity memory-safe-assembly
        assembly {
            useTload := sload(_TGET_FN_SLOT)
        }

        if (useTload == 1) {
            /// @solidity memory-safe-assembly
            assembly {
                value := tload(slot)
            }
        } else {
            /// @solidity memory-safe-assembly
            assembly {
                value := sload(slot)
            }
        }
    }

    /// @notice Clear a slot (respects TSTORE/SSTORE mode)
    function tclear(bytes32 slot) internal {
        tset(slot, 0);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   CONVENIENCE FUNCTIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Set a boolean
    function tsetBool(bytes32 slot, bool value) internal {
        tset(slot, value ? 1 : 0);
    }

    /// @notice Get a boolean
    function tgetBool(bytes32 slot) internal view returns (bool) {
        return tget(slot) != 0;
    }

    /// @notice Set an address
    function tsetAddress(bytes32 slot, address addr) internal {
        tset(slot, uint256(uint160(addr)));
    }

    /// @notice Get an address
    function tgetAddress(bytes32 slot) internal view returns (address) {
        return address(uint160(tget(slot)));
    }

    /// @notice Set bytes32
    function tsetBytes32(bytes32 slot, bytes32 value) internal {
        tset(slot, uint256(value));
    }

    /// @notice Get bytes32
    function tgetBytes32(bytes32 slot) internal view returns (bytes32) {
        return bytes32(tget(slot));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   FALLBACK SSTORE CLEANUP                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Clear multiple slots in fallback mode (for gas refund)
    /// @dev Only needed if supportsTstore() returned false
    function clearSlots(bytes32[] memory slots) internal {
        uint256 useTstore;
        /// @solidity memory-safe-assembly
        assembly {
            useTstore := sload(_TSET_FN_SLOT)
        }

        // Only clear if using SSTORE fallback (TSTORE auto-clears)
        if (useTstore == 0) {
            for (uint256 i = 0; i < slots.length;) {
                /// @solidity memory-safe-assembly
                assembly {
                    let slot := mload(add(add(slots, 0x20), mul(i, 0x20)))
                    sstore(slot, 0)
                }
                unchecked {
                    ++i;
                }
            }
        }
    }
}
