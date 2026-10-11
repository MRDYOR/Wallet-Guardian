'use strict';

/*
 * Permit2 scanner — the "gasless approval" surface drainers love.
 *
 * Permit2 (0x000000000022D473030F116dDEE9F6B43aC78BA3, same on every EVM chain)
 * holds allowances OFF the token contract: allowance(owner, token, spender)
 * => (amount uint160, expiration uint48, nonce uint48). We find (token,spender)
 * pairs from Permit2 Approval/Permit events, then read the live allowance.
 * Keyless, same getLogs approach as ERC-20.
 */

const { ethers } = require('ethers');
const { lookupSpender } = require('./labels');
const { getProvider } = require('./rpc');

const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
const APPROVAL_TOPIC = '0xda9fa7c1b00402c17d0161b249b1ab8bbec047c5a52207b9c112deffd817036b';
const PERMIT_TOPIC = '0xc6a377bfc4eb120024a8ac08eef205be16b817020812c73223e81d1bdb9708ec';
const UINT160_MAX = (2n ** 160n - 1n);

const PERMIT2_ABI = [
  'function allowance(address owner, address token, address spender) view returns (uint160 amount, uint48 expiration, uint48 nonce)',
];
const ERC20_ABI = ['function symbol() view returns (string)', 'function decimals() view returns (uint8)'];

async function scanPermit2(address, chainCfg, buildApproval, opts = {}) {
  const p = getProvider((chainCfg && chainCfg.rpc) || 'https://ethereum-rpc.publicnode.com', chainCfg && chainCfg.chainId);
  const owner = ethers.getAddress(address);
  const ownerTopic = ethers.zeroPadValue(owner, 32);
  const latest = await p.getBlockNumber();
  const windowBlocks = opts.windowBlocks || 120000;
  const step = 50000;
  const fromBlock = Math.max(0, latest - windowBlocks);

  const logs = [];
  for (let start = fromBlock; start <= latest; start += step) {
    const end = Math.min(start + step - 1, latest);
    for (const topic of [APPROVAL_TOPIC, PERMIT_TOPIC]) {
      try {
        logs.push(...await p.getLogs({ address: PERMIT2, topics: [topic, ownerTopic], fromBlock: start, toBlock: end }));
      } catch (e) {}
    }
  }

  // topics: [sig, owner, token, spender]
  const pairs = new Map();
  for (const log of logs) {
    if (!log.topics[2] || !log.topics[3]) continue;
    const token = ethers.getAddress('0x' + log.topics[2].slice(26));
    const spender = ethers.getAddress('0x' + log.topics[3].slice(26));
    pairs.set(`${token}:${spender}`, { token, spender, blockNumber: log.blockNumber });
  }

  const permit2 = new ethers.Contract(PERMIT2, PERMIT2_ABI, p);
  const now = Math.floor(Date.now() / 1000);
  const out = [];
  for (const { token, spender, blockNumber } of pairs.values()) {
    try {
      const [amount, expiration] = await permit2.allowance(owner, token, spender);
      if (amount === 0n) continue;
      if (expiration !== 0n && Number(expiration) < now) continue; // expired
      const erc20 = new ethers.Contract(token, ERC20_ABI, p);
      const [symbol, decimals] = await Promise.all([
        erc20.symbol().catch(() => '???'), erc20.decimals().catch(() => 18),
      ]);
      const block = await p.getBlock(blockNumber).catch(() => null);
      const lbl = lookupSpender(spender);
      const ap = buildApproval({
        kind: 'permit2', token, spender, allowance: amount,
        meta: { name: symbol + ' (via Permit2)', symbol, decimals: Number(decimals) },
        approvedAt: block ? block.timestamp * 1000 : null, txHash: null,
        spenderVerified: null, recognized: lbl.known, spenderLabel: lbl.known ? lbl.name : 'Permit2 spender',
        highValue: new Set((chainCfg && chainCfg.highValue) || []),
      });
      ap.permit2 = true;
      ap.expiration = expiration ? Number(expiration) : 0;
      out.push(ap);
    } catch (e) {}
  }
  return out;
}

module.exports = { scanPermit2, PERMIT2 };
