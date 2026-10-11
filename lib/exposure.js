'use strict';

/*
 * Exposure calculation (§8) — real dollars at risk, honestly.
 *
 *  exposureUsd = (what the spender can ACTUALLY take right now) × price
 *    - unlimited allowance  -> your CURRENT balance of that token (not "whole wallet")
 *    - limited allowance    -> min(allowance, balance)
 *
 * We never imply "unlimited = entire wallet drained". Exposure is per-permission
 * and bounded by the actual balance of the specific asset it controls.
 *
 * Balances via balanceOf (RPC, keyless). Prices via DefiLlama (keyless, no key).
 */

const { ethers } = require('ethers');
const { getProvider } = require('./rpc');

const ERC20_BAL_ABI = ['function balanceOf(address) view returns (uint256)'];

/** Compute exposure fields on an approval given balanceUi + priceUsd already set. */
function computeExposure(a) {
  const price = Number(a.priceUsd || 0);
  const bal = Number(a.balanceUi || 0);
  a.balanceUsd = +(bal * price).toFixed(2);
  if (a.kind === 'nft' || a.kind === 'spl-delegate' || a.kind === 'delegation') {
    // NFT floor / SPL valuation / delegations (no asset movement) — no $ exposure.
    a.exposureUsd = null;
    return a;
  }
  let takeableUi;
  if (a.isUnlimited) {
    takeableUi = bal;
  } else {
    let allowanceUi = 0;
    try { allowanceUi = Number(ethers.formatUnits(a.allowanceRaw || '0', a.decimals || 18)); } catch { allowanceUi = 0; }
    takeableUi = Math.min(allowanceUi, bal);
  }
  a.exposureUsd = +(takeableUi * price).toFixed(2);
  return a;
}

/** Live path: fetch balances + prices for EVM approvals, then compute exposure. */
async function enrichEvmExposure(approvals, owner, chainCfg) {
  const priceable = approvals.filter(a => a.kind === 'token' || a.kind === 'lp' || a.kind === 'permit2');
  if (!priceable.length) return approvals;
  const p = getProvider((chainCfg && chainCfg.rpc) || 'https://ethereum-rpc.publicnode.com', chainCfg && chainCfg.chainId);
  const tokens = [...new Set(priceable.map(a => a.token.toLowerCase()))].slice(0, 25);

  // Balances (parallel, best-effort).
  const balByToken = {};
  await Promise.all(tokens.map(async t => {
    try {
      const c = new ethers.Contract(t, ERC20_BAL_ABI, p);
      const raw = await c.balanceOf(owner);
      const dec = (priceable.find(a => a.token.toLowerCase() === t) || {}).decimals || 18;
      balByToken[t] = Number(ethers.formatUnits(raw, dec));
    } catch { balByToken[t] = 0; }
  }));

  // Prices via DefiLlama (one call).
  const priceByToken = await fetchPrices(chainCfg.id, tokens);

  for (const a of priceable) {
    a.balanceUi = balByToken[a.token.toLowerCase()] || 0;
    a.priceUsd = priceByToken[a.token.toLowerCase()] || 0;
    computeExposure(a);
  }
  return approvals;
}

async function fetchPrices(chainId, tokens) {
  const chainMap = { ethereum: 'ethereum', base: 'base', arbitrum: 'arbitrum', polygon: 'polygon', optimism: 'optimism' };
  const chain = chainMap[chainId] || 'ethereum';
  const coins = tokens.map(t => `${chain}:${t}`).join(',');
  const out = {};
  try {
    const r = await fetch(`https://coins.llama.fi/prices/current/${coins}`, { signal: AbortSignal.timeout(6000) });
    const j = await r.json();
    for (const [k, v] of Object.entries(j.coins || {})) {
      const addr = k.split(':')[1];
      if (addr) out[addr.toLowerCase()] = v.price;
    }
  } catch (e) { /* offline → exposure shows as 0/unknown */ }
  return out;
}

module.exports = { computeExposure, enrichEvmExposure, fetchPrices };
