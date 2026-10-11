'use strict';

/*
 * DbChain — the storage abstraction for the exploit-pattern database.
 *
 * The whole point of the hackathon integration lives here: the app talks to a
 * `DbChain` interface, and we can back it by a LOCAL store (runs today) or by
 * ARKIV DB-Chains (decentralized, composable, permissionless) with zero changes
 * to the rest of the app.
 *
 *   interface DbChain {
 *     queryExploits(filter) -> Promise<Entity[]>
 *     getExploit(id)        -> Promise<Entity | null>
 *     createExploit(entity) -> Promise<{ entityKey }>
 *   }
 *
 * An "entity" mirrors Arkiv's model exactly: a JSON payload plus typed
 * attributes you can query on (protocol, pattern, lossUsd, chain).
 */

const fs = require('fs');
const path = require('path');

// ─────────────────────────────────────────────────────────────────────────────
// Local adapter — reads the bundled seed file. Always available, no network.
// ─────────────────────────────────────────────────────────────────────────────
class LocalDbChain {
  constructor(seedPath) {
    this.seedPath = seedPath || path.join(__dirname, '..', 'data', 'exploits.json');
    this._cache = null;
    this.backend = 'local';
  }

  _load() {
    if (!this._cache) {
      this._cache = JSON.parse(fs.readFileSync(this.seedPath, 'utf8'));
    }
    return this._cache;
  }

  async queryExploits(filter = {}) {
    let rows = this._load();
    if (filter.pattern) rows = rows.filter(r => r.pattern === filter.pattern);
    if (filter.patterns) rows = rows.filter(r => filter.patterns.includes(r.pattern));
    if (filter.minLossUsd) rows = rows.filter(r => r.lossUsd >= filter.minLossUsd);
    if (filter.chain) rows = rows.filter(r => r.chain === filter.chain);
    // Sort by loss descending — biggest, most memorable hacks first.
    return rows.slice().sort((a, b) => b.lossUsd - a.lossUsd);
  }

  async getExploit(id) {
    return this._load().find(r => r.id === id) || null;
  }

  async createExploit(entity) {
    // Local store is read-only for the demo; writes would go to Arkiv in prod.
    throw new Error('LocalDbChain is read-only. Enable the Arkiv adapter to write exploit entities on-chain.');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Arkiv adapter — talks to real DB-Chains via @arkiv-network/sdk.
//
// Written against Arkiv's published SDK API. It is lazy-loaded so the app runs
// fine WITHOUT the SDK installed or the network live. Flip it on by setting:
//   ARKIV_ENABLED=true
//   ARKIV_PRIVATE_KEY=0x...        (a funded testnet key, for writes)
//   ARKIV_CHAIN=braga             (or whatever the Sept-2026 testnet is named)
//
// Braga testnet was retired 2026-08-12; the next public testnet lands Sept 2026.
// The moment it's up, install the SDK and set the env vars — no other changes.
// ─────────────────────────────────────────────────────────────────────────────
class ArkivDbChain {
  constructor(opts = {}) {
    this.backend = 'arkiv';
    this.chainName = opts.chain || process.env.ARKIV_CHAIN || 'braga';
    this.privateKey = opts.privateKey || process.env.ARKIV_PRIVATE_KEY;
    this._public = null;
    this._wallet = null;
  }

  async _clients() {
    if (this._public) return { publicClient: this._public, walletClient: this._wallet };
    // Lazy require — only pulled in when Arkiv is actually enabled.
    const { createPublicClient, createWalletClient } = require('@arkiv-network/sdk');
    const chains = require('@arkiv-network/sdk/chains');
    const { http } = require('viem');
    const chain = chains[this.chainName];
    this._public = createPublicClient({ chain, transport: http() });
    if (this.privateKey) {
      const { privateKeyToAccount } = require('viem/accounts');
      this._wallet = createWalletClient({
        chain,
        transport: http(),
        account: privateKeyToAccount(this.privateKey),
      });
    }
    return { publicClient: this._public, walletClient: this._wallet };
  }

  _entityToExploit(entity) {
    const payload = entity.toJson();
    const attrs = Object.fromEntries((entity.attributes || []).map(a => [a.key, a.value]));
    return { ...payload, id: attrs.id || payload.id, pattern: attrs.pattern, protocol: attrs.protocol, lossUsd: Number(attrs.lossUsd), _entityKey: entity.key };
  }

  async queryExploits(filter = {}) {
    const { publicClient } = await this._clients();
    const { eq, gt } = require('@arkiv-network/sdk/query');
    const conds = [eq('type', 'exploit')];
    if (filter.pattern) conds.push(eq('pattern', filter.pattern));
    if (filter.minLossUsd) conds.push(gt('lossUsd', filter.minLossUsd));
    const result = await publicClient
      .select({ key: true, payload: true, attributes: true })
      .where(...conds)
      .limit(50)
      .fetch();
    return result.entities.map(e => this._entityToExploit(e)).sort((a, b) => b.lossUsd - a.lossUsd);
  }

  async getExploit(id) {
    const rows = await this.queryExploits({});
    return rows.find(r => r.id === id) || null;
  }

  async createExploit(exploit) {
    const { walletClient } = await this._clients();
    if (!walletClient) throw new Error('ARKIV_PRIVATE_KEY required to write exploit entities.');
    const { jsonToPayload, ExpirationTime } = require('@arkiv-network/sdk/utils');
    const { entityKey } = await walletClient.createEntity({
      payload: jsonToPayload(exploit),
      contentType: 'application/json',
      attributes: [
        { key: 'type', value: 'exploit' },
        { key: 'id', value: exploit.id },
        { key: 'protocol', value: exploit.protocol },
        { key: 'pattern', value: exploit.pattern },
        { key: 'lossUsd', value: exploit.lossUsd },
        { key: 'chain', value: exploit.chain || 'ethereum' },
      ],
      expiresIn: ExpirationTime.fromDays(365),
    });
    return { entityKey };
  }
}

function makeDbChain() {
  if (String(process.env.ARKIV_ENABLED).toLowerCase() === 'true') {
    try {
      return new ArkivDbChain();
    } catch (e) {
      console.error('[dbchain] Arkiv adapter failed to init, falling back to local:', e.message);
    }
  }
  return new LocalDbChain();
}

module.exports = { LocalDbChain, ArkivDbChain, makeDbChain };
