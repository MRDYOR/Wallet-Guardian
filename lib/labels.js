'use strict';

/*
 * Contract intelligence — a curated, keyless registry of well-known spenders.
 *
 * §12 Contract Intelligence + §30 False-Positive Protection:
 *  - Recognized protocols are labelled and treated as lower-risk.
 *  - UNKNOWN spenders are marked "unrecognized" (a mild caution), NEVER
 *    asserted as malicious just for being unknown. We only claim what we can
 *    actually establish. Real source-verification needs an explorer key and is
 *    layered on later via an optional adapter.
 */

// address(lowercase) -> { name, protocol, category }
const KNOWN = {
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': { name: 'Uniswap V2 Router', protocol: 'Uniswap', category: 'DEX router' },
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': { name: 'Uniswap V3 Router', protocol: 'Uniswap', category: 'DEX router' },
  '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad': { name: 'Uniswap Universal Router', protocol: 'Uniswap', category: 'DEX router' },
  '0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b': { name: 'Uniswap Universal Router', protocol: 'Uniswap', category: 'DEX router' },
  '0x66a9893cc07d91d95644aedd05d03f95e1dba8af': { name: 'Uniswap Universal Router v2', protocol: 'Uniswap', category: 'DEX router' },
  '0x1111111254eeb25477b68fb85ed929f73a960582': { name: '1inch Aggregation Router v5', protocol: '1inch', category: 'DEX aggregator' },
  '0x111111125421ca6dc452d289314280a0f8842a65': { name: '1inch Aggregation Router v6', protocol: '1inch', category: 'DEX aggregator' },
  '0xdef1c0ded9bec7f1a1670819833240f027b25eff': { name: '0x Exchange Proxy', protocol: '0x Protocol', category: 'DEX aggregator' },
  '0x000000000022d473030f116ddee9f6b43ac78ba3': { name: 'Permit2', protocol: 'Uniswap', category: 'Approval router' },
  '0xc92e8bdf79f0507f65a392b0ab4667716bfe0110': { name: 'CoW Protocol Vault Relayer', protocol: 'CoW Swap', category: 'DEX' },
  '0x881d40237659c251811cec9c364ef91dc08d300c': { name: 'MetaMask Swap Router', protocol: 'MetaMask', category: 'DEX aggregator' },
  '0x00000000006c3852cbef3e08e8df289169ede581': { name: 'Seaport 1.1', protocol: 'OpenSea', category: 'NFT marketplace' },
  '0x00000000000001ad428e4906ae43d8f9852d0dd6': { name: 'Seaport 1.4', protocol: 'OpenSea', category: 'NFT marketplace' },
  '0x00000000000000adc04c56bf30ac9d3c0aaf14dc': { name: 'Seaport 1.5', protocol: 'OpenSea', category: 'NFT marketplace' },
  '0x1e0049783f008a0085193e00003d00cd54003c71': { name: 'OpenSea Conduit', protocol: 'OpenSea', category: 'NFT marketplace' },
  '0x7f268357a8c2552623316e2562d90e642bb538e5': { name: 'Wyvern Exchange v2', protocol: 'OpenSea (legacy)', category: 'NFT marketplace' },
  '0xe592427a0aece92de3edee1f18e0157c05861564': { name: 'Uniswap V3 SwapRouter', protocol: 'Uniswap', category: 'DEX router' },
  '0xdef171fe48cf0115b1d80b88dc8eab59176fee57': { name: 'ParaSwap v5', protocol: 'ParaSwap', category: 'DEX aggregator' },
  '0x216b4b4ba9f3e719726886d34a177484278bfcae': { name: 'ParaSwap TokenTransferProxy', protocol: 'ParaSwap', category: 'DEX aggregator' },
  '0x6131b5fae19ea4f9d964eac0408e4408b66337b5': { name: 'KyberSwap Router', protocol: 'KyberSwap', category: 'DEX aggregator' },
  '0xba12222222228d8ba445958a75a0704d566bf2c8': { name: 'Balancer Vault', protocol: 'Balancer', category: 'DEX' },
  '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2': { name: 'Aave v3 Pool', protocol: 'Aave', category: 'Lending' },
  '0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9': { name: 'Aave v2 LendingPool', protocol: 'Aave', category: 'Lending' },
};

function lookupSpender(address) {
  if (!address) return { known: false };
  const hit = KNOWN[address.toLowerCase()];
  if (hit) return { known: true, verified: true, ...hit };
  return { known: false };
}

module.exports = { lookupSpender, KNOWN };
