# Gasless Cross-Chain Intents with Gelato

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER EXPERIENCE                              │
│  "I want to swap 100 USDC on Ethereum for ETH on Base"              │
│  User signs intent → ZERO GAS REQUIRED → Tokens appear on Base      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    GELATO SMART WALLET SDK                          │
│  • ERC-2771 trusted forwarder: 0xd8253782c45a12053594b9deB72d8e8aB2Fca54c │
│  • Gas sponsored via your Polygon 1Balance                          │
│  • Works with any EOA via EIP-7702 or Smart Accounts                │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 CROSSCHAININTENTSETTLER                             │
│  • ERC-7683 compliant origin/destination settler                    │
│  • ERC-2771 meta-transaction support (Gelato compatible)            │
│  • Integrates with FlashArbExecutor for arb fills                   │
└─────────────────────────────────────────────────────────────────────┘
```

## Integration Code

### 1. Frontend - User Submits Gasless Intent

```typescript
import { createGelatoSmartWalletClient, sponsored } from "@gelatonetwork/smartwallet";
import { gelato } from "@gelatonetwork/smartwallet/accounts";
import { createWalletClient, createPublicClient, http, encodeFunctionData } from "viem";
import { base } from "viem/chains";

// CrossChainIntentSettler ABI (relevant functions)
const SETTLER_ABI = [
  {
    name: "open",
    type: "function",
    inputs: [
      {
        name: "order",
        type: "tuple",
        components: [
          { name: "fillDeadline", type: "uint32" },
          { name: "orderDataType", type: "bytes32" },
          { name: "orderData", type: "bytes" },
        ],
      },
    ],
    outputs: [],
  },
] as const;

// Your deployed settler address
const SETTLER_ADDRESS = "0x..."; // Deploy on Base

async function submitGaslessIntent(
  userPrivateKey: string,
  swapParams: {
    tokenIn: string;
    tokenOut: string;
    amountIn: bigint;
    minAmountOut: bigint;
    destinationChain: number;
    recipient: string;
  },
) {
  // 1. Setup Gelato Smart Wallet
  const owner = privateKeyToAccount(userPrivateKey);
  const publicClient = createPublicClient({ chain: base, transport: http() });

  const account = await gelato({
    owner,
    client: publicClient,
  });

  const walletClient = createWalletClient({
    account,
    chain: base,
    transport: http(),
  });

  const smartWalletClient = createGelatoSmartWalletClient(walletClient, {
    apiKey: process.env.GELATO_API_KEY!,
  });

  // 2. Encode the swap intent
  const SIMPLE_SWAP_TYPE = "0x73696d706c655f73776170000000000000000000000000000000000000000000";

  const orderData = encodeAbiParameters(
    [
      { name: "tokenIn", type: "address" },
      { name: "tokenOut", type: "address" },
      { name: "amountIn", type: "uint256" },
      { name: "minAmountOut", type: "uint256" },
      { name: "destinationChainId", type: "uint256" },
      { name: "recipient", type: "address" },
    ],
    [
      swapParams.tokenIn,
      swapParams.tokenOut,
      swapParams.amountIn,
      swapParams.minAmountOut,
      BigInt(swapParams.destinationChain),
      swapParams.recipient,
    ],
  );

  const fillDeadline = Math.floor(Date.now() / 1000) + 3600; // 1 hour

  // 3. Submit via Gelato (GASLESS!)
  const result = await smartWalletClient.execute({
    payment: sponsored(process.env.GELATO_API_KEY!), // Your sponsor pays
    calls: [
      // First: Approve tokens to settler
      {
        to: swapParams.tokenIn,
        data: encodeFunctionData({
          abi: [
            {
              name: "approve",
              type: "function",
              inputs: [
                { name: "spender", type: "address" },
                { name: "amount", type: "uint256" },
              ],
              outputs: [{ type: "bool" }],
            },
          ],
          functionName: "approve",
          args: [SETTLER_ADDRESS, swapParams.amountIn],
        }),
        value: 0n,
      },
      // Second: Open the cross-chain order
      {
        to: SETTLER_ADDRESS,
        data: encodeFunctionData({
          abi: SETTLER_ABI,
          functionName: "open",
          args: [
            {
              fillDeadline,
              orderDataType: SIMPLE_SWAP_TYPE,
              orderData,
            },
          ],
        }),
        value: 0n,
      },
    ],
  });

  console.log("Gasless intent submitted! UserOp:", result?.id);
  const txHash = await result?.wait();
  console.log("Transaction confirmed:", txHash);

  return txHash;
}
```

### 2. Solver Backend - Listens and Fills

```typescript
// Your IntentBby solver already handles this via Gelato Relay
// The CrossChainIntentSettler emits Open events that your solver can listen to

interface OpenEvent {
  orderId: bytes32;
  resolvedOrder: {
    user: address;
    originChainId: number;
    openDeadline: number;
    fillDeadline: number;
    orderId: bytes32;
    maxSpent: Array<{ token: address; amount: bigint; recipient: address; chainId: number }>;
    minReceived: Array<{ token: address; amount: bigint; recipient: address; chainId: number }>;
    fillInstructions: Array<{
      destinationChainId: number;
      destinationSettler: address;
      originData: bytes;
    }>;
  };
}

// Your solver fills via FlashArbExecutor on destination chain
```

## Key Benefits

| Feature     | Before                    | After (Gelato)                           |
| ----------- | ------------------------- | ---------------------------------------- |
| User Gas    | User pays ETH             | **Sponsor pays (your Polygon 1Balance)** |
| UX          | Multi-step approve + swap | **Single gasless signature**             |
| Batching    | Manual                    | **Automatic (approve + open in 1 tx)**   |
| Cross-Chain | User bridges first        | **Invisible - solver handles**           |

## Contract Addresses

| Contract                 | Address                                      | Network    |
| ------------------------ | -------------------------------------------- | ---------- |
| CrossChainIntentSettler  | TBD (deploy)                                 | Base       |
| Gelato Trusted Forwarder | `0xd8253782c45a12053594b9deB72d8e8aB2Fca54c` | All chains |
| FlashArbExecutor V2      | `0x69Ed0906448cd292f0F413d7060875439954e30B` | Base       |

## Gas Sponsorship Flow

```
1. User signs intent (no gas)
2. Gelato Smart Wallet SDK bundles: approve + open
3. Your Polygon 1Balance sponsors the Base transaction
4. CrossChainIntentSettler.open() called via trusted forwarder
5. Settler uses _msgSender() to get real user (ERC-2771)
6. Intent emitted → Your solver fills via FlashArbExecutor
7. User receives tokens on destination chain
```

## Deploy Commands

```bash
# Deploy CrossChainIntentSettler with Gelato forwarder
cd /Users/hs/Documents/GITHUB/PROJECT-INTENT/bebe
forge script script/DeployCrossChainSettler.s.sol:DeployCrossChainSettler \
  --rpc-url base \
  --broadcast \
  --verify
```
