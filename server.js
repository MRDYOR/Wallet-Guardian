'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const { scanApprovals, buildApproval, classify, matchExploits } = require('./lib/approvals');
const { makeDbChain } = require('./lib/dbchain');
const { getChain, listChains } = require('./lib/chains');
const { scanSolanaDelegates, isValidSolanaAddress, getRecentBlockhash } = require('./lib/solana');
const { scanPermit2 } = require('./lib/permit2');
const { scanDelegations, buildDelegation } = require('./lib/delegations');
const { enrichEvmExposure, computeExposure } = require('./lib/exposure');
const { ethers } = require('ethers');

// Static prices for the demo tokens (real prices come from DefiLlama live).
const DEMO_PRICES = { USDC: 1, USDT: 1, DAI: 1, WETH: 3000, UNI: 8, BAYC: 0 };

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const seedChain = makeDbChain(); // curated seed (data/exploits.json)
const DEMO = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'demo.json'), 'utf8'));

// Dashboard API (server-side only) for the Risk Monitor's DB.
const DASH = process.env.DASHBOARD_BASE || `http://localhost:${process.env.DASHBOARD_PORT || 4000}`;
const TOKEN = process.env.DASHBOARD_TOKEN;
const GROUP = process.env.ARTIFACT_GROUP || 'main';
const DASH_AUTH = { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' };

async function dbQuery(sql, params = []) {
  const r = await fetch(`${DASH}/api/db/${GROUP}/database/query?sql=${encodeURIComponent(sql)}&params=${encodeURIComponent(JSON.stringify(params))}`, { headers: DASH_AUTH });
  const j = await r.json();
  return j.rows || [];
}
async function dbExec(sql, params = []) {
  const r = await fetch(`${DASH}/api/db/${GROUP}/database/execute`, { method: 'POST', headers: DASH_AUTH, body: JSON.stringify({ sql, params }) });
  return r.json();
}

// ── Exploit intelligence = curated seed ∪ auto-ingested (wg_exploits table) ──
// The scanner reads the union so the feed self-updates without manual edits.
const dbchain = {
  backend: seedChain.backend,
  async queryExploits(filter = {}) {
    const seed = await seedChain.queryExploits(filter);
    let ingested = [];
    try {
      const rows = await dbQuery('SELECT * FROM wg_exploits ORDER BY loss_usd DESC LIMIT 200');
      ingested = rows.map(r => ({ id: r.id, protocol: r.protocol, date: r.date, lossUsd: r.loss_usd, chain: r.chain, pattern: r.pattern, vector: r.vector, summary: r.summary, lesson: r.lesson, link: r.link }));
      if (filter.pattern) ingested = ingested.filter(r => r.pattern === filter.pattern);
      if (filter.patterns) ingested = ingested.filter(r => filter.patterns.includes(r.pattern));
      if (filter.minLossUsd) ingested = ingested.filter(r => r.lossUsd >= filter.minLossUsd);
      if (filter.chain) ingested = ingested.filter(r => r.chain === filter.chain);
    } catch (e) { /* table may not exist yet */ }
    const map = new Map();
    [...seed, ...ingested].forEach(e => map.set(e.id, e));
    return [...map.values()].sort((a, b) => (b.lossUsd || 0) - (a.lossUsd || 0));
  },
  async getExploit(id) { return (await this.queryExploits({})).find(e => e.id === id) || null; },
};

// Map a DefiLlama hack to one of OUR approval patterns. Conservative: only tag an
// approval-matching pattern when the incident clearly involves user approvals;
// everything else is 'protocol-exploit' (shown in the feed, never falsely matched
// to a user's approval, since user approvals never carry that pattern).
function classifyHack(h) {
  const t = `${h.classification || ''} ${h.technique || ''} ${h.name || ''}`.toLowerCase();
  if (/phish|drain|approval|permit|transferfrom|infinite|allowance|wallet compromise/.test(t)) return 'unverified-contract';
  if (/access control|private key|compromis/.test(t) && (h.targetType === 'Token' || /protocol|defi|lending|bridge|router|aggregator/.test(t))) return 'unlimited-erc20';
  if (/upgrade|proxy|logic/.test(t)) return 'upgradeable-defi';
  return 'protocol-exploit'; // feed-only; won't match user approvals
}

console.log(`[wallet-guardian] exploit DbChain backend = ${dbchain.backend}`);

// Attach exploit matches to a list of approvals.
async function withExploits(approvals) {
  for (const a of approvals) {
    a.exploits = await matchExploits(a, dbchain);
  }
  return approvals;
}

// Exposure + classification + sort. Runs after exploit matching.
async function finalize(approvals, { owner, chain, demo } = {}) {
  try {
    if (demo) {
      for (const a of approvals) { a.priceUsd = DEMO_PRICES[a.tokenSymbol] || 0; computeExposure(a); }
    } else if (chain && chain.family === 'evm' && owner) {
      await enrichEvmExposure(approvals, owner, chain);
    }
  } catch (e) { /* exposure best-effort */ }
  approvals.forEach(classify);
  // Sort: critical → revoke → review → safe, then by exposure, then score.
  const rank = { critical: 0, revoke: 1, review: 2, safe: 3 };
  approvals.sort((x, y) => (rank[x.recGroup] - rank[y.recGroup]) || ((y.exposureUsd || 0) - (x.exposureUsd || 0)) || (y.score - x.score));
  return approvals;
}

// Wallet Security Overview (§25).
function overview(approvals) {
  const o = { total: approvals.length, safe: 0, review: 0, revoke: 0, critical: 0, totalExposedUsd: 0, stale: 0, exploitExposure: 0 };
  for (const a of approvals) {
    o[a.recGroup === 'safe' ? 'safe' : a.recGroup]++;
    if (a.exposureUsd) o.totalExposedUsd += a.exposureUsd;
    if (a.ageDays != null && a.ageDays > 90) o.stale++;
    if (a.exploits && a.exploits.length) o.exploitExposure++;
  }
  o.totalExposedUsd = +o.totalExposedUsd.toFixed(2);
  o.health = Math.max(0, Math.min(100, Math.round(100 - (o.critical * 30 + o.revoke * 12 + o.review * 4))));
  return o;
}

// Build demo approvals through the same scoring pipeline as live data.
const { lookupSpender } = require('./lib/labels');
function demoApprovals() {
  return DEMO.approvals.map(d => {
    if (d.kind === 'delegation') {
      return buildDelegation({ dtype: d.dtype, to: d.spender, from: DEMO.address, rights: '0x'.padEnd(66, '0'), contract: d.token || '0x0000000000000000000000000000000000000000', tokenId: '0', amount: '0' });
    }
    const lbl = lookupSpender(d.spender);
    const a = buildApproval({
      kind: d.kind || 'token',
      token: d.token,
      spender: d.spender,
      allowance: d.kind === 'nft' ? 'ALL' : BigInt(d.allowance),
      meta: d.meta,
      approvedAt: Date.now() - (d.ageDays * 86400000),
      txHash: null,
      spenderVerified: d.spenderVerified,
      recognized: lbl.known,
      spenderLabel: lbl.known ? lbl.name : d.spenderLabel,
    });
    a.balanceUi = d.balanceUi != null ? d.balanceUi : 0;
    return a;
  });
}

// ── Scan an address (or demo) ────────────────────────────────────────────────
// GET /api/scan?address=0x...   |   GET /api/scan?demo=true
app.get('/api/scan', async (req, res) => {
  try {
    const demo = String(req.query.demo).toLowerCase() === 'true';
    if (demo) {
      let approvals = await withExploits(demoApprovals());
      approvals = await finalize(approvals, { demo: true });
      return res.json({ mode: 'demo', address: DEMO.address, dbchain: dbchain.backend, approvals, summary: summarize(approvals), overview: overview(approvals), scannedAt: new Date().toISOString() });
    }
    const address = (req.query.address || '').trim();
    const chainId = (req.query.chain || 'ethereum').toLowerCase();
    const chain = getChain(chainId);
    let approvals = [];
    let note = null;

    if (chain.family === 'solana') {
      if (!isValidSolanaAddress(address)) {
        return res.status(400).json({ error: 'Provide a valid Solana address, or use demo mode.' });
      }
      try {
        approvals = await scanSolanaDelegates(address);
      } catch (e) {
        note = 'Solana scan failed (public RPC limits/rate). Try again shortly or use Demo Mode.';
      }
      approvals = await withExploits(approvals);
      approvals = await finalize(approvals, { owner: address, chain });
      if (!approvals.length && !note) note = 'No active SPL token delegates found on this Solana address — nothing to revoke.';
      return res.json({ mode: 'live', chain: chain.id, chainLabel: chain.label, address, dbchain: dbchain.backend, approvals, summary: summarize(approvals), overview: overview(approvals), scannedAt: new Date().toISOString(), note });
    }

    // EVM path
    if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
      return res.status(400).json({ error: 'Provide a valid 0x wallet address, or use demo mode.' });
    }
    try {
      const windowBlocks = Math.min(parseInt(req.query.window) || 120000, 2000000); // optional deep scan
      const [erc, permit2, delegs] = await Promise.all([
        scanApprovals(address, chain, { windowBlocks }).catch(() => []),
        scanPermit2(address, chain, buildApproval, { windowBlocks }).catch(() => []),
        scanDelegations(address, chain).catch(() => []),
      ]);
      approvals = [...erc, ...permit2, ...delegs];
    } catch (e) {
      note = 'Live scan failed (public RPC limits). Showing what we could read.';
    }
    approvals = await withExploits(approvals);
    approvals = await finalize(approvals, { owner: address, chain });
    if (!approvals.length && !note) {
      note = `No active approvals found in the recent block window on ${chain.label}'s public RPC. For full-history results, add an RPC/explorer key — or try Demo Mode to see the full experience.`;
    }
    res.json({ mode: 'live', chain: chain.id, chainLabel: chain.label, address, dbchain: dbchain.backend, approvals, summary: summarize(approvals), overview: overview(approvals), scannedAt: new Date().toISOString(), note });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── The exploit database (backed by DbChain: local now, Arkiv later) ─────────
app.get('/api/exploits', async (req, res) => {
  try {
    const rows = await dbchain.queryExploits({});
    res.json({ dbchain: dbchain.backend, count: rows.length, exploits: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Auto-ingest recent hacks from DefiLlama (keyless). BOUNDED: one fetch, capped
// rows, hard timeout. Called once/day by a scheduled task so the feed self-updates.
// Plain-English explanation of a hack technique/classification for non-experts.
function explainHack(h) {
  const t = `${h.classification || ''} ${h.technique || ''}`.toLowerCase();
  const rules = [
    [/phish|drain/, 'Users were tricked — on a fake or hacked website — into signing an approval or transaction that handed their tokens to the attacker.'],
    [/permit|signature/, 'Victims signed an off-chain approval (a Permit / EIP-712 signature) that looked harmless but let the attacker move their tokens with no on-chain trace.'],
    [/private key|compromis|access control/, "The keys or admin permissions controlling the protocol were stolen or misused, giving the attacker direct control over the contract and the funds (and approvals) inside it."],
    [/flash ?loan/, 'The attacker borrowed a huge sum with no collateral inside a single transaction (a flash loan), used it to distort prices or logic, drained value, and repaid the loan — all at once.'],
    [/oracle|price/, "The attacker fed the protocol a fake price through its data feed (oracle), then traded against that wrong price to extract funds."],
    [/reentran/, 'The attacker\'s contract re-called a function before the protocol finished updating its balances, letting them withdraw the same funds repeatedly in a loop.'],
    [/governance/, 'The attacker gained enough voting power (often with a flash loan) to pass a malicious proposal that drained the treasury.'],
    [/rug|exit scam/, "The project's own operators drained user funds and disappeared."],
    [/upgrade|proxy|logic/, 'The contract was upgradeable — the attacker (or a compromised admin) swapped in malicious logic that drained funds users had deposited or approved.'],
    [/bridge/, "A flaw in the cross-chain bridge let the attacker mint or withdraw assets that weren't actually backed, draining the bridge's pooled funds."],
    [/contract vuln|smart contract|logic error/, "A bug in the smart contract's code let the attacker withdraw funds they were never entitled to."],
  ];
  for (const [re, txt] of rules) if (re.test(t)) return txt;
  return 'A vulnerability in the protocol let an attacker withdraw funds that were not theirs.';
}

async function ingestHacks() {
  const r = await fetch('https://api.llama.fi/hacks', { signal: AbortSignal.timeout(15000) });
  const all = await r.json();
  const cutoff = Date.now() / 1000 - 60 * 60 * 24 * 365 * 2.5; // last ~2.5 years
  const recent = all.filter(h => h.date > cutoff && (h.amount || 0) >= 1_000_000)
    .sort((a, b) => b.date - a.date).slice(0, 80);
  let added = 0;
  for (const h of recent) {
    const id = 'dl-' + String(h.defillamaId || `${h.name}-${h.date}`).replace(/[^a-z0-9]/gi, '').toLowerCase();
    const dateIso = new Date(h.date * 1000).toISOString().slice(0, 10);
    const pattern = classifyHack(h);
    const chain = (Array.isArray(h.chain) ? (h.chain[0] || 'ethereum') : (h.chain || 'ethereum')).toLowerCase();
    const vector = h.technique || h.classification || 'Exploit';
    const amtM = ((h.amount || 0) / 1e6).toFixed(1);
    const summary = `On ${dateIso}, ${h.name} lost about $${amtM}M on ${chain.charAt(0).toUpperCase() + chain.slice(1)}. ${explainHack(h)}${h.returnedFunds ? ' Some funds were later returned.' : ''}`;
    const lesson = pattern === 'protocol-exploit'
      ? 'This was a protocol-level exploit, not a direct drain of user approvals — included so you can see the current threat landscape. The safest habit is to hold approvals only where you actively use a protocol, and revoke the rest.'
      : 'Wallets that held standing (especially unlimited) approvals to this contract or its type were exposed. If you have an approval matching this pattern, review it and revoke what you no longer use.';
    const link = h.source || `https://defillama.com/hacks`;
    const out = await dbExec(
      `INSERT INTO wg_exploits (id,protocol,date,loss_usd,chain,pattern,vector,summary,lesson,link,source) VALUES (?,?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(id) DO UPDATE SET protocol=excluded.protocol, date=excluded.date, loss_usd=excluded.loss_usd, chain=excluded.chain, pattern=excluded.pattern, vector=excluded.vector, summary=excluded.summary, lesson=excluded.lesson, link=excluded.link`,
      [id, h.name, dateIso, Math.round(h.amount || 0), chain, pattern, vector, summary, lesson, link, h.source ? 'defillama+source' : 'defillama']);
    if (out && (out.changes || out.lastInsertRowid)) added += 1;
  }
  return { scanned: recent.length, added };
}
app.all('/api/exploits/ingest', async (req, res) => {
  try { res.json({ ok: true, ...(await ingestHacks()) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/chains', (req, res) => res.json({ chains: listChains() }));

// Post-revoke verification (§10, §2) — re-read the on-chain allowance after a revoke tx.
app.get('/api/allowance', async (req, res) => {
  try {
    const chain = getChain((req.query.chain || 'ethereum').toLowerCase());
    if (chain.family !== 'evm') return res.status(400).json({ error: 'EVM only' });
    const { owner, token, spender, kind } = req.query;
    const p = new ethers.JsonRpcProvider(chain.rpc);
    if (kind === 'nft') {
      const c = new ethers.Contract(token, ['function isApprovedForAll(address,address) view returns (bool)'], p);
      const active = await c.isApprovedForAll(owner, spender);
      return res.json({ active: !!active, allowance: active ? 'ALL' : '0' });
    }
    if (kind === 'permit2') {
      const c = new ethers.Contract('0x000000000022D473030F116dDEE9F6B43aC78BA3', ['function allowance(address,address,address) view returns (uint160,uint48,uint48)'], p);
      const [amount] = await c.allowance(owner, token, spender);
      return res.json({ active: amount > 0n, allowance: amount.toString() });
    }
    const c = new ethers.Contract(token, ['function allowance(address,address) view returns (uint256)'], p);
    const amount = await c.allowance(owner, spender);
    res.json({ active: amount > 0n, allowance: amount.toString() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Recent Solana blockhash so the browser can build a Revoke tx for Phantom to sign.
app.get('/api/solana/blockhash', async (req, res) => {
  try { res.json(await getRecentBlockhash()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Risk Monitor ─────────────────────────────────────────────────────────────
// Reusable scan (EVM + Permit2, or Solana) → scored, exploit-matched approvals.
async function scanAddress(address, chainId) {
  const chain = getChain(chainId);
  if (chain.family === 'solana') return withExploits(await scanSolanaDelegates(address).catch(() => []));
  const [erc, permit2, delegs] = await Promise.all([
    scanApprovals(address, chain).catch(() => []),
    scanPermit2(address, chain, buildApproval).catch(() => []),
    scanDelegations(address, chain).catch(() => []),
  ]);
  return withExploits([...erc, ...permit2, ...delegs]);
}
const keyOf = a => `${a.kind}:${(a.token || '').toLowerCase()}:${(a.spender || '').toLowerCase()}`;

// Start watching a wallet; snapshot its current approvals as the baseline.
app.post('/api/monitor', async (req, res) => {
  try {
    const address = (req.body.address || '').trim();
    const chain = (req.body.chain || 'ethereum').toLowerCase();
    if (!address) return res.status(400).json({ error: 'address required' });
    await dbExec('INSERT OR IGNORE INTO wg_watched (address, chain, label) VALUES (?,?,?)', [address, chain, req.body.label || null]);
    const approvals = await scanAddress(address, chain);
    for (const a of approvals) {
      await dbExec('INSERT OR IGNORE INTO wg_snapshots (address, chain, approval_key, risk) VALUES (?,?,?,?)', [address, chain, keyOf(a), a.level]);
    }
    res.json({ ok: true, watching: true, address, chain, baseline: approvals.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// List watch state + open alerts for an address.
app.get('/api/monitor', async (req, res) => {
  try {
    const address = (req.query.address || '').trim();
    const watched = await dbQuery('SELECT * FROM wg_watched WHERE address = ? ORDER BY created_at DESC', [address]);
    const alerts = await dbQuery('SELECT * FROM wg_alerts WHERE address = ? ORDER BY created_at DESC LIMIT 50', [address]);
    res.json({ watching: watched.length > 0, watched, alerts });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Re-scan every watched wallet, diff vs snapshot, raise alerts for NEW risky/exploit-matched approvals.
// Called by the scheduled watcher task (and available for manual runs).
app.post('/api/monitor/scan', async (req, res) => {
  try {
    const watched = (await dbQuery('SELECT DISTINCT address, chain FROM wg_watched', [])).slice(0, 5); // bound fan-out
    let raised = 0;
    for (const w of watched) {
      const approvals = await scanAddress(w.address, w.chain);
      const known = new Set((await dbQuery('SELECT approval_key FROM wg_snapshots WHERE address=? AND chain=?', [w.address, w.chain])).map(r => r.approval_key));
      for (const a of approvals) {
        const k = keyOf(a);
        if (known.has(k)) continue; // already seen
        await dbExec('INSERT OR IGNORE INTO wg_snapshots (address, chain, approval_key, risk) VALUES (?,?,?,?)', [w.address, w.chain, k, a.level]);
        if (a.exploits && a.exploits.length && a.level === 'high') {
          const ex = a.exploits[0];
          await dbExec('INSERT INTO wg_alerts (address, chain, severity, title, detail, token, spender, exploit_id) VALUES (?,?,?,?,?,?,?,?)',
            [w.address, w.chain, 'high', `New high-risk approval on ${a.tokenSymbol}`,
             `Matches the pattern behind ${ex.protocol} ($${(ex.lossUsd/1e6).toFixed(0)}M). Review and revoke.`, a.token, a.spender, ex.id]);
          raised++;
        }
      }
    }
    res.json({ ok: true, watchedCount: watched.length, alertsRaised: raised });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Demo: raise a sample alert so users can SEE how notification works.
app.post('/api/monitor/simulate', async (req, res) => {
  try {
    const address = (req.body.address || DEMO.address).trim();
    const chain = (req.body.chain || 'ethereum').toLowerCase();
    const ex = (await dbchain.queryExploits({ pattern: 'unlimited-erc20' }))[0] || { protocol: 'Multichain', lossUsd: 126000000, id: 'multichain-2023' };
    await dbExec('INSERT INTO wg_alerts (address, chain, severity, title, detail, token, spender, exploit_id) VALUES (?,?,?,?,?,?,?,?)',
      [address, chain, 'high', 'A wallet with your USDC approval was just drained',
       `Another wallet holding the same unlimited USDC approval pattern was exploited (${ex.protocol}-style, $${(ex.lossUsd/1e6).toFixed(0)}M class). Revoke now to stay safe.`,
       '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', '0x000000000000Ad05Ccc4F10045630fb830B95127', ex.id]);
    res.json({ ok: true, simulated: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/monitor/ack', async (req, res) => {
  try { await dbExec('UPDATE wg_alerts SET acknowledged=1 WHERE id=?', [req.body.id]); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/health', (req, res) => res.json({ ok: true, dbchain: dbchain.backend }));

function summarize(approvals) {
  const s = { total: approvals.length, high: 0, medium: 0, low: 0, unlimited: 0, exploitMatches: 0 };
  for (const a of approvals) {
    s[a.level]++;
    if (a.isUnlimited) s.unlimited++;
    if (a.exploits && a.exploits.length) s.exploitMatches++;
  }
  return s;
}

app.use(express.static(path.join(__dirname, 'public')));
app.listen(PORT, () => console.log(`[wallet-guardian] listening on ${PORT}`));

// Self-updating exploit feed: one lightweight DefiLlama fetch on boot + every 24h.
// Bounded (single fetch, ≤80 idempotent upserts) — no background agent, no RPC storm.
setTimeout(() => { ingestHacks().then(r => console.log('[wallet-guardian] exploit ingest:', JSON.stringify(r))).catch(e => console.log('[wallet-guardian] ingest failed:', e.message)); }, 30000);
setInterval(() => { ingestHacks().catch(() => {}); }, 24 * 60 * 60 * 1000);
