// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {FlashArbExecutor} from "../src/FlashArbExecutor.sol";

contract DeployFlashArbExecutor is Script {
    function run() external returns (FlashArbExecutor executor) {
        uint256 deployerPrivateKey = vm.envOr("PRIVATE_KEY", uint256(0));

        // If no private key, use default anvil account for local testing
        if (deployerPrivateKey == 0) {
            console.log("No PRIVATE_KEY set, using default anvil account");
            deployerPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        }

        vm.startBroadcast(deployerPrivateKey);

        // Deploy FlashArbExecutor
        executor = new FlashArbExecutor();
        console.log("FlashArbExecutor deployed at:", address(executor));

        // Initialize defaults (DEX registry, bloom filter, etc.)
        // This needs to be called via execute since it's "Only self"
        bytes memory initCall = abi.encodeWithSelector(FlashArbExecutor.initializeDefaults.selector);
        bytes memory executeCall = abi.encodeWithSignature(
            "execute(bytes32,bytes)",
            bytes32(0), // mode = 0 (default batch execution)
            abi.encode(
                abi.encodePacked(
                    address(executor), // target
                    uint256(0), // value
                    initCall // data
                )
            )
        );

        console.log("To initialize, call execute with initializeDefaults");
        console.log("Or call via ERC7821 batch execution");

        vm.stopBroadcast();

        return executor;
    }
}
