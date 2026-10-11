'use strict';

/*
 * Solana scanner — SPL token DELEGATES are the analog of ERC-20 approvals.
 * A token account can name a `delegate` allowed to move up to `delegatedAmount`.
 * We read them keyless in ONE getParsedTokenAccountsByOwner call (no logs).
 *
 * Token metadata (symbol) is resolved from Jupiter's free strict token list,
 * fetched once and cached — no API key.
 */

const { Connection, PublicKey } = require('@solana/web3.js');
const { SOLANA } = require('./chains');

const TOKEN_PROGRAM = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const TOKEN_2022_PROGRAM = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
const U64_MAX = '18446744073709551615';

let _tokenList = null;
async function tokenList() {
  if (_tokenList) return _tokenList;
  _tokenList = new Map();
  try {
    const res = await fetch('https://token.jup.ag/strict', { signal: AbortSignal.timeout(6000) });
    const arr = await res.json();
    for (const t of arr) _tokenList.set(t.address, { symbol: t.symbol, name: t.name, decimals: t.decimals });
  } catch (e) { /* offline → mints shown raw */ }
  return _tokenList;
}

function isValidSolanaAddress(a) {
  try { new PublicKey(a); return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a); } catch { return false; }
}

async function scanSolanaDelegates(address) {
  const conn = new Connection(SOLANA.rpc, 'confirmed');
  const owner = new PublicKey(address);
  const list = await tokenList();

  const results = [];
  for (const programId of [TOKEN_PROGRAM, TOKEN_2022_PROGRAM]) {
    let accounts;
    try {
      accounts = await conn.getParsedTokenAccountsByOwner(owner, { programId });
    } catch (e) { continue; }
    for (const { pubkey, account } of accounts.value) {
      const info = account.data.parsed.info;
      if (!info.delegate) continue; // no active approval on this account
      const mint = info.mint;
      const meta = list.get(mint) || { symbol: mint.slice(0, 4) + '…', name: 'SPL Token', decimals: info.tokenAmount.decimals };
      const delegatedRaw = info.delegatedAmount ? info.delegatedAmount.amount : '0';
      const isUnlimited = delegatedRaw === U64_MAX;
      results.push(buildSolanaApproval({ mint, tokenAccount: pubkey.toBase58(), delegate: info.delegate, meta, delegatedRaw, delegatedUi: info.delegatedAmount ? info.delegatedAmount.uiAmountString : '0', isUnlimited }));
    }
  }
  return results;
}

function buildSolanaApproval({ mint, tokenAccount, delegate, meta, delegatedRaw, delegatedUi, isUnlimited }) {
  const reasons = [];
  let score = 0;
  if (isUnlimited) { score += 50; reasons.push({ tag: 'unlimited', text: 'Unlimited delegate — this address can move ALL of this token from your account.' }); }
  else { score += 20; reasons.push({ tag: 'limited', text: `Delegate can move up to ${delegatedUi} ${meta.symbol}.` }); }
  reasons.push({ tag: 'unverified', text: 'Solana delegates are set on your token account — revoke any you do not recognize.' });
  const level = score >= 50 ? 'high' : score >= 20 ? 'medium' : 'low';
  return {
    kind: 'spl-delegate', chain: 'solana',
    token: mint, tokenAccount, spender: delegate, txHash: null,
    tokenName: meta.name, tokenSymbol: meta.symbol, decimals: meta.decimals,
    allowanceRaw: delegatedRaw,
    allowanceDisplay: isUnlimited ? 'Unlimited' : (delegatedUi || '0'),
    isUnlimited, isHighValue: false, ageDays: null, approvedAt: null,
    spenderVerified: null, spenderLabel: 'Solana delegate',
    score, level, reasons,
    patterns: isUnlimited ? ['unlimited-erc20'] : [], // reuse unlimited-drain exploit context
  };
}

// Server-side: fetch a recent blockhash so the browser can build a revoke tx
// without calling an external RPC directly (respects the no-browser-RPC rule).
async function getRecentBlockhash() {
  const conn = new Connection(SOLANA.rpc, 'confirmed');
  const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash('confirmed');
  return { blockhash, lastValidBlockHeight };
}

module.exports = { scanSolanaDelegates, isValidSolanaAddress, getRecentBlockhash };
