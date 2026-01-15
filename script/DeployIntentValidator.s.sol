// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {IntentValidator} from "../src/IntentValidator.sol";

/// @title Deploy IntentValidator
/// @notice Deploys IntentValidator with CrossChainIntentSettler as constructor arg
contract DeployIntentValidator is Script {
    // CrossChainIntentSettler on Base mainnet
    address constant CROSS_CHAIN_SETTLER = 0x0AC0f7BA945E5F7FD6bE2d7c987045B586F34175;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deployer:", deployer);
        console.log("Settler:", CROSS_CHAIN_SETTLER);

        vm.startBroadcast(deployerPrivateKey);

        IntentValidator validator = new IntentValidator(CROSS_CHAIN_SETTLER);

        console.log("IntentValidator deployed at:", address(validator));

        vm.stopBroadcast();

        // Verification info
        console.log("\n=== Verification ===");
        console.log("forge verify-contract", address(validator), "src/IntentValidator.sol:IntentValidator");
        console.log("--constructor-args $(cast abi-encode 'constructor(address)' ", CROSS_CHAIN_SETTLER, ")");
    }
}
