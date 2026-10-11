'use strict';

/*
 * Delegations (§18) — a SEPARATE permission category, not a token approval.
 *
 * Reads delegate.cash / delegate.xyz v2 registry outgoing delegations, keyless.
 * CRITICAL correctness note (§30, §32): a delegate.cash delegation grants
 * off-chain / claim / identity rights (airdrops, token-gated access). It does
 * NOT let the delegate move or spend your assets. We frame it accordingly and
 * never imply it can drain funds.
 */

const { ethers } = require('ethers');
const { getProvider } = require('./rpc');

const REGISTRY = '0x00000000000000447e69651d841bD8D104Bed493'; // delegate v2 (same on all EVM)
const ABI = ['function getOutgoingDelegations(address) view returns (tuple(uint8 type_,address to,address from,bytes32 rights,address contract_,uint256 tokenId,uint256 amount)[])'];
const TYPE = { 1: 'All rights', 2: 'Contract-scoped', 3: 'ERC-721', 4: 'ERC-20', 5: 'ERC-1155' };

async function scanDelegations(owner, chainCfg) {
  try {
    const p = getProvider((chainCfg && chainCfg.rpc) || 'https://ethereum-rpc.publicnode.com', chainCfg && chainCfg.chainId);
    const c = new ethers.Contract(REGISTRY, ABI, p);
    const rows = await c.getOutgoingDelegations(ethers.getAddress(owner));
    return rows.filter(d => Number(d.type_) >= 1).map(d => buildDelegation({
      dtype: Number(d.type_), to: d.to, from: d.from, rights: d.rights,
      contract: d.contract_, tokenId: d.tokenId.toString(), amount: d.amount.toString(),
    }));
  } catch (e) { return []; }
}

function buildDelegation({ dtype, to, from, rights, contract, tokenId, amount }) {
  const scope = TYPE[dtype] || 'Custom';
  const isAll = dtype === 1;
  const reasons = [];
  if (isAll) reasons.push({ tag: 'scope-all', text: 'Delegates ALL claim/identity rights for your wallet to this address.' });
  else reasons.push({ tag: 'scope', text: `Scoped delegation (${scope}${contract && contract !== ethers.ZeroAddress ? ' · ' + contract.slice(0, 8) + '…' : ''}).` });
  reasons.push({ tag: 'unrecognized', text: 'Delegate is an external address — confirm it is a wallet you control.' });
  reasons.push({ tag: 'note', text: 'delegate.cash grants off-chain/claim authority only — it cannot move or spend your assets.' });

  return {
    kind: 'delegation', chain: undefined,
    token: (contract && contract !== ethers.ZeroAddress) ? contract : null,
    spender: to, txHash: null,
    tokenName: isAll ? 'Wallet delegation' : 'Delegation', tokenSymbol: scope.toUpperCase(), decimals: 0,
    allowanceRaw: 'DELEGATION',
    allowanceDisplay: scope,
    isUnlimited: false, isHighValue: false, ageDays: null, approvedAt: null,
    spenderVerified: null, spenderLabel: null, recognized: false,
    exposureUsd: null,
    // No asset exposure → risk is modest: broad (ALL) = review, scoped = keep.
    score: isAll ? 30 : 12, level: isAll ? 'medium' : 'low',
    reasons, patterns: [],
    deleg: { dtype, to, contract: (contract && contract !== ethers.ZeroAddress) ? contract : ethers.ZeroAddress, rights: rights || ethers.ZeroHash, tokenId, amount },
  };
}

module.exports = { scanDelegations, buildDelegation, REGISTRY };
