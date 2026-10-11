'use strict';

/*
 * Permissions engine — Wallet Guardian scanner core.
 *
 * Scans the on-chain PERMISSIONS an address has granted:
 *   • ERC-20 token allowances        (approve)            kind: token
 *   • NFT collection operators       (setApprovalForAll)  kind: nft
 *   • LP / DeFi / dApp spender routers are the same token approvals,
 *     labelled by who the spender is.                     kind: lp / dapp
 *
 * Everything on-chain runs SERVER-SIDE. The browser only calls relative /api.
 *
 * NOTE ON SCOPE: Off-chain grants (which dApps your wallet is "connected" to,
 * CEX/API keys, WalletConnect sessions) are NOT derivable from an address —
 * they live in your wallet/session, not on-chain. Those are surfaced/educated
 * separately, never inferred from a scan.
 */

const { ethers } = require('ethers');
const { lookupSpender } = require('./labels');
const { getProvider } = require('./rpc');

const UNLIMITED_THRESHOLD = (2n ** 255n);
const APPROVAL_TOPIC = ethers.id('Approval(address,address,uint256)');
const APPROVAL_FOR_ALL_TOPIC = ethers.id('ApprovalForAll(address,address,bool)');

const HIGH_VALUE = new Set([
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', // USDC
  '0xdac17f958d2ee523a2206206994597c13d831ec7', // USDT
  '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', // WETH
  '0x6b175474e89094c44da98b954eedeac495271d0f', // DAI
  '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599', // WBTC
]);

const ERC20_ABI = [
  'function name() view returns (string)',
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function allowance(address owner, address spender) view returns (uint256)',
];
const ERC721_ABI = [
  'function name() view returns (string)',
  'function symbol() view returns (string)',
  'function isApprovedForAll(address owner, address operator) view returns (bool)',
];

function provider(chainCfg) {
  return getProvider((chainCfg && chainCfg.rpc) || process.env.ETH_RPC_URL || 'https://ethereum-rpc.publicnode.com', chainCfg && chainCfg.chainId);
}

/** Best-effort live scan of ERC-20 allowances + NFT operators over a recent window. */
async function scanApprovals(address, chainCfg, opts = {}) {
  const p = provider(chainCfg);
  const highValue = new Set((chainCfg && chainCfg.highValue) || [...HIGH_VALUE]);
  const owner = ethers.getAddress(address);
  const ownerTopic = ethers.zeroPadValue(owner, 32);
  const latest = await p.getBlockNumber();
  const windowBlocks = opts.windowBlocks || 120000;
  const fromBlock = Math.max(0, latest - windowBlocks);
  const step = 50000;

  const erc20Logs = [];
  const nftLogs = [];
  for (let start = fromBlock; start <= latest; start += step) {
    const end = Math.min(start + step - 1, latest);
    try {
      erc20Logs.push(...await p.getLogs({ topics: [APPROVAL_TOPIC, ownerTopic], fromBlock: start, toBlock: end }));
    } catch (e) {}
    try {
      nftLogs.push(...await p.getLogs({ topics: [APPROVAL_FOR_ALL_TOPIC, ownerTopic], fromBlock: start, toBlock: end }));
    } catch (e) {}
  }

  const out = [];
  const metaCache = new Map();

  // ── ERC-20 token / LP / dApp approvals ──
  const erc20Pairs = latestByPair(erc20Logs);
  for (const pair of erc20Pairs.values()) {
    try {
      const c = new ethers.Contract(pair.token, ERC20_ABI, p);
      const allowance = await c.allowance(owner, pair.spender);
      if (allowance === 0n) continue;
      let meta = metaCache.get(pair.token) || await erc20Meta(c);
      metaCache.set(pair.token, meta);
      const lbl = lookupSpender(pair.spender);
      out.push(buildApproval({
        kind: 'token', token: pair.token, spender: pair.spender, allowance, meta,
        approvedAt: await blockTime(p, pair.blockNumber), txHash: pair.txHash,
        spenderVerified: null, recognized: lbl.known, spenderLabel: lbl.known ? lbl.name : null, highValue,
      }));
    } catch (e) {}
  }

  // ── NFT setApprovalForAll operators ──
  const nftPairs = latestByPair(nftLogs, /*isNft*/ true);
  for (const pair of nftPairs.values()) {
    try {
      const c = new ethers.Contract(pair.token, ERC721_ABI, p);
      const active = await c.isApprovedForAll(owner, pair.spender);
      if (!active) continue;
      let meta = metaCache.get(pair.token) || await erc721Meta(c);
      metaCache.set(pair.token, meta);
      const lbl = lookupSpender(pair.spender);
      out.push(buildApproval({
        kind: 'nft', token: pair.token, spender: pair.spender, allowance: 'ALL', meta,
        approvedAt: await blockTime(p, pair.blockNumber), txHash: pair.txHash,
        spenderVerified: null, recognized: lbl.known, spenderLabel: lbl.known ? lbl.name : null,
      }));
    } catch (e) {}
  }

  return out;
}

function latestByPair(logs, isNft = false) {
  const m = new Map();
  for (const log of logs) {
    if (!log.topics[2]) continue;
    if (isNft && !/1$/.test(BigInt(log.data).toString())) { /* approved==false → skip below */ }
    const token = ethers.getAddress(log.address);
    const spender = ethers.getAddress('0x' + log.topics[2].slice(26));
    // For ApprovalForAll, data is the bool `approved`; only keep approvals (true=1).
    if (isNft && BigInt(log.data) === 0n) { m.delete(`${token}:${spender}`); continue; }
    const key = `${token}:${spender}`;
    const prev = m.get(key);
    if (!prev || log.blockNumber > prev.blockNumber) {
      m.set(key, { token, spender, blockNumber: log.blockNumber, txHash: log.transactionHash });
    }
  }
  return m;
}

async function blockTime(p, n) { try { const b = await p.getBlock(n); return b ? b.timestamp * 1000 : null; } catch { return null; } }
async function erc20Meta(c) {
  const [name, symbol, decimals] = await Promise.all([
    c.name().catch(() => 'Unknown Token'), c.symbol().catch(() => '???'), c.decimals().catch(() => 18),
  ]);
  return { name, symbol, decimals: Number(decimals) };
}
async function erc721Meta(c) {
  const [name, symbol] = await Promise.all([
    c.name().catch(() => 'Unknown Collection'), c.symbol().catch(() => 'NFT'),
  ]);
  return { name, symbol, decimals: 0 };
}

/** Turn a raw permission into a scored, enriched, exploit-matched record. */
function buildApproval({ kind = 'token', token, spender, allowance, meta, approvedAt, txHash, spenderVerified, spenderLabel, recognized, highValue }) {
  const hv = highValue instanceof Set ? highValue : HIGH_VALUE;
  const isNft = kind === 'nft';
  const isPermit2 = kind === 'permit2';
  const PERMIT2_MAX = (2n ** 160n - 1n);
  const allowanceBig = isNft ? null : (typeof allowance === 'bigint' ? allowance : BigInt(allowance));
  const isUnlimited = isNft ? true : (isPermit2 ? allowanceBig >= PERMIT2_MAX : allowanceBig >= UNLIMITED_THRESHOLD);
  const isHighValue = !isNft && hv.has(token.toLowerCase());
  const ageDays = approvedAt ? Math.floor((Date.now() - approvedAt) / 86400000) : null;

  const reasons = [];
  let score = 0;
  // Permission risk (§6): unlimited is ELEVATED but not automatically dangerous.
  if (isNft) {
    score += 35;
    reasons.push({ tag: 'unlimited', text: 'setApprovalForAll — this operator can move EVERY NFT in the collection.' });
  } else if (isUnlimited) {
    score += 30;
    reasons.push({ tag: 'unlimited', text: 'Unlimited allowance — spender can move your full balance of this token.' });
  }
  // Contract intelligence (§12) + false-positive protection (§30): reward
  // recognized protocols; flag unrecognized as a MILD caution — never assert malice.
  if (recognized) {
    reasons.push({ tag: 'recognized', text: `Recognized spender: ${spenderLabel}. Known protocol — lower risk.` });
  } else if (spenderVerified === false) {
    score += 35; reasons.push({ tag: 'unverified', text: 'Spender contract source is not verified — you cannot see what it does.' });
  } else {
    score += 20; reasons.push({ tag: 'unrecognized', text: 'Unrecognized spender — not a known protocol. Verify before trusting it.' });
  }
  if (ageDays !== null && ageDays > 90) { score += 20; reasons.push({ tag: 'stale', text: `Granted ${ageDays} days ago and still active — likely forgotten.` }); }
  if (isHighValue) { score += 10; reasons.push({ tag: 'high-value', text: `${meta.symbol} is a high-value token — a drain here is costly.` }); }
  if (!isNft && !isUnlimited && allowanceBig > 0n) { reasons.push({ tag: 'limited', text: 'Limited allowance — capped, but still a standing permission.' }); }

  let level = score >= 55 ? 'high' : score >= 25 ? 'medium' : 'low';
  // Trust cap: a recognized, legitimate protocol is never auto-"high" just for being unlimited.
  if (recognized && level === 'high') level = 'medium';

  const patterns = [];
  if (isNft) patterns.push('setapprovalforall-nft');
  // Only match the generic unlimited-drain exploits for UNRECOGNIZED spenders —
  // don't tag a normal Uniswap approval as "the pattern that drained $126M".
  if (!isNft && isUnlimited && !recognized) patterns.push('unlimited-erc20');
  if (spenderVerified === false) patterns.push('unverified-contract');

  return {
    kind, token, spender, txHash,
    tokenName: meta.name, tokenSymbol: meta.symbol, decimals: meta.decimals,
    allowanceRaw: isNft ? 'ALL' : allowanceBig.toString(),
    allowanceDisplay: isNft ? 'All items' : (isUnlimited ? 'Unlimited' : formatUnits(allowanceBig, meta.decimals)),
    isUnlimited, isHighValue, ageDays, approvedAt,
    spenderVerified, spenderLabel: spenderLabel || null, recognized: !!recognized,
    score, level, reasons, patterns,
  };
}

// Final classification (§6 CRITICAL, §11/§26 recommendation) — run after exposure known.
// Provenance sources per signal (§31) — never hide why we flagged something.
const SIGNAL_SOURCE = {
  unlimited: 'On-chain permission', limited: 'On-chain permission',
  'scope-all': 'On-chain permission', scope: 'On-chain permission',
  recognized: 'Verified protocol identity',
  unrecognized: 'Contract intelligence', unverified: 'Contract intelligence',
  stale: 'On-chain behavior', 'high-value': 'On-chain behavior',
};

function classify(a) {
  const exploited = a.exploits && a.exploits.length;
  // CRITICAL only for UNRECOGNIZED spenders that match an exploit pattern and hold real exposure.
  if (!a.recognized && a.level === 'high' && exploited && a.isUnlimited && (a.exposureUsd === null || a.exposureUsd > 0)) a.level = 'critical';
  a.recommendation = a.level === 'critical' ? 'REVOKE NOW' : a.level === 'high' ? 'REVOKE' : a.level === 'medium' ? 'REVIEW' : 'KEEP';
  a.recGroup = a.level === 'critical' ? 'critical' : a.level === 'high' ? 'revoke' : a.level === 'medium' ? 'review' : 'safe';

  // Contributing signals + provenance (§30, §31).
  const signals = [];
  if (a.isUnlimited) signals.push(a.kind === 'nft' ? 'operator over entire collection' : 'unlimited allowance');
  if (!a.recognized) signals.push('unrecognized spender');
  if (a.spenderVerified === false) signals.push('unverified source');
  if (a.ageDays != null && a.ageDays > 90) signals.push('stale (' + a.ageDays + 'd)');
  if (exploited) signals.push('matches known exploit pattern');
  a.signals = signals;

  const sources = new Set();
  (a.reasons || []).forEach(r => { if (SIGNAL_SOURCE[r.tag]) sources.add(SIGNAL_SOURCE[r.tag]); });
  if (exploited) sources.add('Known exploit database (Arkiv)');
  a.sources = [...sources];

  // Confidence in the RISK assessment (§30) — never over-claim "malicious".
  // Recognized, non-exploited spenders are an identity we can verify, not a threat.
  if (a.recognized && !exploited) {
    a.confidence = 'IDENTITY VERIFIED';
  } else {
    const riskSig = (a.isUnlimited ? 1 : 0) + (!a.recognized ? 1 : 0) + (a.spenderVerified === false ? 1 : 0) + (exploited ? 1 : 0);
    a.confidence = riskSig >= 2 ? 'HIGH CONFIDENCE' : riskSig === 1 ? 'SUSPICIOUS' : 'UNKNOWN';
  }
  return a;
}

function formatUnits(v, decimals) {
  try {
    const n = Number(ethers.formatUnits(v, decimals));
    if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(2) + 'K';
    return n.toLocaleString(undefined, { maximumFractionDigits: 4 });
  } catch { return String(v); }
}

async function matchExploits(approval, dbchain) {
  if (!approval.patterns.length) return [];
  const matches = await dbchain.queryExploits({ patterns: approval.patterns });
  if (matches && matches.length) return matches;
  const all = [];
  for (const pat of approval.patterns) all.push(...await dbchain.queryExploits({ pattern: pat }));
  return all;
}

module.exports = { scanApprovals, buildApproval, classify, matchExploits, UNLIMITED_THRESHOLD, HIGH_VALUE };
