'use strict';

/*
 * Chain registry — all keyless / free public RPCs.
 * EVM chains share the same Approval / ApprovalForAll log-scan path.
 * Solana is handled separately (SPL token delegates).
 */

const EVM_CHAINS = {
  ethereum: {
    id: 'ethereum', label: 'Ethereum', family: 'evm', chainId: 1,
    rpc: process.env.ETH_RPC_URL || 'https://ethereum-rpc.publicnode.com',
    explorer: 'https://etherscan.io',
    highValue: [
      '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', // USDC
      '0xdac17f958d2ee523a2206206994597c13d831ec7', // USDT
      '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', // WETH
      '0x6b175474e89094c44da98b954eedeac495271d0f', // DAI
      '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599', // WBTC
    ],
  },
  base: {
    id: 'base', label: 'Base', family: 'evm', chainId: 8453,
    rpc: 'https://base-rpc.publicnode.com',
    explorer: 'https://basescan.org',
    highValue: [
      '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', // USDC
      '0x4200000000000000000000000000000000000006', // WETH
    ],
  },
  arbitrum: {
    id: 'arbitrum', label: 'Arbitrum', family: 'evm', chainId: 42161,
    rpc: 'https://arbitrum-one-rpc.publicnode.com',
    explorer: 'https://arbiscan.io',
    highValue: [
      '0xaf88d065e77c8cc2239327c5edb3a432268e5831', // USDC
      '0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9', // USDT
      '0x82af49447d8a07e3bd95bd0d56f35241523fbab1', // WETH
    ],
  },
  polygon: {
    id: 'polygon', label: 'Polygon', family: 'evm', chainId: 137,
    rpc: 'https://polygon-bor-rpc.publicnode.com',
    explorer: 'https://polygonscan.com',
    highValue: [
      '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359', // USDC
      '0xc2132d05d31c914a87c6611c10748aeb04b58e8f', // USDT
      '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619', // WETH
    ],
  },
  optimism: {
    id: 'optimism', label: 'Optimism', family: 'evm', chainId: 10,
    rpc: 'https://optimism-rpc.publicnode.com',
    explorer: 'https://optimistic.etherscan.io',
    highValue: [
      '0x0b2c639c533813f4aa9d7837caf62653d097ff85', // USDC
      '0x94b008aa00579c1307b0ef2c499ad98a8ce58e58', // USDT
      '0x4200000000000000000000000000000000000006', // WETH
    ],
  },
};

const SOLANA = {
  id: 'solana', label: 'Solana', family: 'solana',
  rpc: process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com',
  explorer: 'https://solscan.io',
};

function getChain(id) {
  if (id === 'solana') return SOLANA;
  return EVM_CHAINS[id] || EVM_CHAINS.ethereum;
}

function listChains() {
  return [...Object.values(EVM_CHAINS).map(c => ({ id: c.id, label: c.label, family: c.family })),
          { id: SOLANA.id, label: SOLANA.label, family: SOLANA.family }];
}

module.exports = { EVM_CHAINS, SOLANA, getChain, listChains };
