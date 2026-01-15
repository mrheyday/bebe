// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {CrossChainIntentSettler} from "../src/CrossChainIntentSettler.sol";

/// @title Deploy Cross-Chain Intent Settler
/// @notice Deploys ERC-7683 compliant cross-chain intent settler with Gelato trusted forwarder
contract DeployCrossChainSettler is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address owner = vm.addr(deployerPrivateKey);
        
        // FlashArbExecutor V2 on Base
        address flashArbExecutor = 0x69Ed0906448cd292f0F413d7060875439954e30B;
        
        // Gelato Trusted Forwarder (same address across all chains)
        // https://docs.gelato.network/developer-services/relay/quick-start/trusted-forwarders
        address gelatoTrustedForwarder = 0xd8253782c45a12053594b9deB72d8e8aB2Fca54c;

        vm.startBroadcast(deployerPrivateKey);

        CrossChainIntentSettler settler = new CrossChainIntentSettler(
            owner, 
            flashArbExecutor,
            gelatoTrustedForwarder
        );

        console.log("========================================");
        console.log("ERC-7683 Cross-Chain Intent Settler");
        console.log("========================================");
        console.log("Deployed to:", address(settler));
        console.log("Owner:", owner);
        console.log("FlashArbExecutor:", flashArbExecutor);
        console.log("Trusted Forwarder:", gelatoTrustedForwarder);
        console.log("Chain ID:", block.chainid);
        console.log("");

        // Configure destination settlers for supported chains
        // Base (8453), Ethereum (1), Optimism (10), Arbitrum (42161), Polygon (137)
        
        if (block.chainid == 8453) {
            // Deploying on Base - set self as destination settler
            settler.setDestinationSettler(8453, address(settler));
            console.log("Set Base (8453) destination settler:", address(settler));
            
            // Placeholder for other chains (update after deploying on each)
            // settler.setDestinationSettler(1, address(0)); // Ethereum
            // settler.setDestinationSettler(10, address(0)); // Optimism
            // settler.setDestinationSettler(42161, address(0)); // Arbitrum
            // settler.setDestinationSettler(137, address(0)); // Polygon
        }

        vm.stopBroadcast();

        console.log("");
        console.log("========================================");
        console.log("INVISIBLE CROSS-CHAIN UX ENABLED");
        console.log("========================================");
        console.log("");
        console.log("Features:");
        console.log("  - Gasless cross-chain swaps (ERC-7683)");
        console.log("  - Multi-hop routing");
        console.log("  - Flash loan arbitrage");
        console.log("  - Solver network integration");
        console.log("");
        console.log("Order Types:");
        console.log("  - SIMPLE_SWAP: Single input -> single output");
        console.log("  - MULTI_HOP_SWAP: Complex multi-chain routing");
        console.log("  - FLASH_ARB: Flash loan arbitrage execution");
    }
}
