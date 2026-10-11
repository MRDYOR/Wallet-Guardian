# Wallet Guardian — Hackathon Submission

## Tagline
A wallet-permission **security intelligence platform** — know exactly what your wallet has authorized, how dangerous each permission is, and revoke what matters. Not just a list with a revoke button.

## One-liner
Wallet Guardian scans any wallet across 5 EVM chains + Solana, tells you what each on-chain permission can actually do, how much money is at risk, whether it matches a real historical exploit — and lets you revoke it, with a decentralized exploit-intelligence database built on **Arkiv**.

---

## The Problem
Token approvals are the single most exploited primitive in crypto. They're invisible, standing permissions: once you approve a contract, it can move your tokens **forever**, with no further signature. Users have lost **billions** this way:

- **BadgerDAO** — $120M (malicious frontend injected unlimited approvals)
- **Multichain** — $126M (old infinite approvals drained after a key compromise)
- **Socket/Bungee** — $3.3M (a bad aggregator route drained active approvals)
- Countless drainer kits, OpenSea `setApprovalForAll` phishing, and Permit2 signature scams

Existing revoke tools show a raw list of approvals and a revoke button. They don't tell you **what** a permission can do, **how much** is at risk, **whether** the contract is trustworthy, or **which real exploit** a permission resembles.

## The Solution
Wallet Guardian is a security **intelligence** system built around the journey:

**SCAN → UNDERSTAND → ASSESS → MONITOR → ALERT → REVOKE**

### What it does
- **Multi-chain scan (keyless):** Ethereum, Base, Arbitrum, Polygon, Optimism, and Solana. Reads ERC-20 allowances, NFT `setApprovalForAll` operators, LP/DeFi/router approvals, **Permit2** allowances, **delegate.cash delegations**, and **Solana SPL delegates**.
- **Exposure calculation:** real dollars at risk = the amount a spender can actually take (allowance ∩ your balance) × price. Never the alarmist "unlimited = whole wallet."
- **Risk engine:** transparent, multi-signal scoring (permission + contract + activity + exposure) → **LOW / MEDIUM / HIGH / CRITICAL**, always with a plain-English "why."
- **Contract intelligence + false-positive protection:** a curated registry recognizes real protocols (Uniswap, 1inch, Permit2, OpenSea, Aave…) and treats them as lower-risk; unknown spenders get a measured caution, never labeled "malicious" without evidence. Every classification carries a **confidence level** and its **data provenance** ("Why we flagged this").
- **Recommendations:** every permission → **KEEP / REVIEW / REVOKE / REVOKE NOW**, grouped Critical → Revoke → Review → Safe.
- **Wallet Security Overview:** a health score (0–100), total $ at risk, and counts across all findings.
- **Exploit intelligence (the differentiator — on Arkiv):** each risky permission is matched by *pattern* against a database of real hacks; click any to read the full case study.
- **Revoke:** single or **batch**, across ERC-20 / NFT / Permit2 / delegations / Solana — with **gas estimation** before signing and **post-revoke verification** (re-reads the on-chain allowance to confirm it's really zero).
- **Risk Sandbox:** an interactive, fully-simulated walkthrough of how an approval drains a wallet — then how revoking stops it.
- **Privacy-first:** 100% read-only. Scanning cannot move your assets; we never request seed phrases or private keys. Revoking is a transaction *you* sign in your own wallet.

---

## How we use Arkiv
The **exploit-pattern database** — Wallet Guardian's core differentiator — is modeled as **Arkiv DB-Chain entities**. Each historical exploit is an entity with a JSON payload plus queryable attributes (`pattern`, `protocol`, `lossUsd`, `chain`), so the scanner queries it exactly like a database:

```
publicClient.select({ key: true, payload: true, attributes: true })
  .where(eq('type', 'exploit'), gt('lossUsd', 1_000_000))
  .fetch()
```

The whole app talks to a single `DbChain` interface with two adapters:
- **`LocalDbChain`** — runs today (bundled seed of real exploits).
- **`ArkivDbChain`** — written against the real `@arkiv-network/sdk` (`createPublicClient` / `createWalletClient`, `createEntity`, `select().where(eq, gt)`), lazy-loaded and enabled with `ARKIV_ENABLED=true`.

**Why this matters:** security intelligence should not live in one company's private database. On Arkiv it becomes **permissionless, composable, and shared** — any wallet or dApp can read the same exploit-pattern DB-Chain, and (roadmap) security researchers can contribute new patterns via author-scoped writes. Data expiration maps cleanly to time-boxed threat alerts.

**Honest status:** the Arkiv adapter is fully implemented against the published SDK. It currently runs on the local Arkiv-compatible store because Arkiv's public testnet (**Braga**) was retired on **2026-08-12** and the next public testnet lands **September 2026**. Going live is a one-flag switch (`ARKIV_ENABLED=true` + a funded testnet key) with **zero rewrite** — the interface already matches Arkiv's API 1:1.

---

## Arkiv Data & Query Design

The design principle: **Arkiv holds shared, curated, composable security intelligence. Everything user-specific, real-time, private, or ephemeral stays off Arkiv.**

### 1. Entities & attributes
Four entity types. **Attributes** are the indexed, queryable fields (strings are `eq`-only; numbers support range comparisons). **Payload** is the rich JSON content.

**`exploit`** — a historical hack (the anchor of the intelligence graph)
- attributes: `type="exploit"`, `pattern` (str), `protocol` (str), `chain` (str), `lossUsd` (num), `date` (num, unix), `severity` (str)
- payload: `{ protocol, date, lossUsd, chain, pattern, vector, summary, lesson, link }`

**`spender`** — reputation record for a spender/contract address (the composable public good)
- attributes: `type="spender"`, `address` (str), `chain` (str), `verdict` (str: trusted|drainer|unknown), `confidence` (num 0-100), `category` (str)
- payload: `{ address, chain, label, protocol, verified, verdict, evidence[], sources[] }`

**`pattern`** — the approval-risk taxonomy the scanner matches against
- attributes: `type="pattern"`, `key` (str, e.g. `unlimited-erc20`), `riskClass` (str)
- payload: `{ key, title, description, indicators[], exploitIds[] }`

**`report`** — a community/researcher-submitted signal (permissionless write path)
- attributes: `type="report"`, `address` (str), `chain` (str), `kind` (str: scam|exploit|drainer), `status` (str: pending|verified)
- payload: `{ address, chain, kind, description, reporter, evidenceUrl }`

### 2. The queries we rely on
```js
import { eq, gt } from "@arkiv-network/sdk/query"

// (a) Match a user's approval to real exploits — the core scan-time query
publicClient.select({ key:true, payload:true, attributes:true })
  .where(eq('type','exploit'), eq('pattern', approval.pattern))
  .limit(10).fetch()

// (b) Is this spender a known drainer? — composable reputation lookup (any dApp can run this)
publicClient.select({ payload:true, attributes:true })
  .where(eq('type','spender'), eq('address', spender), eq('chain', chain))
  .fetch()

// (c) Intelligence panel — the biggest, most memorable hacks
publicClient.select({ payload:true })
  .where(eq('type','exploit'), gt('lossUsd', 1_000_000))
  .limit(10).fetch()

// (d) Moderation queue — unverified community reports
publicClient.select({ payload:true, attributes:true })
  .where(eq('type','report'), eq('status','pending')).fetch()

// (e) Provenance — who contributed this signal (cryptographic authorship)
publicClient.select({ payload:true }).createdBy(researcherAddress)
  .where(eq('type','spender')).fetch()
```
All queries key off small, typed attributes; rich data rides in the payload. Cursor pagination (200/page) covers growth.

### 3. Expiry, extension & ownership
Expiry isn't a limitation — it's the moderation and freshness engine.
- **`exploit` / `pattern`** — long TTL (`ExpirationTime.fromDays(365)`), extended on each curator refresh. Durable facts kept alive by renewal.
- **`spender`** — 90-day TTL, extended only when re-confirmed. **Reputation decays if not refreshed** — no stale "trusted" labels, automatically. A plain DB would need a cron job for this; Arkiv does it natively.
- **`report`** — 30-day TTL. **Unverified reports auto-expire** — a self-cleaning moderation queue with zero infra. On verification, a new long-lived `spender`/`exploit` entity is written.
- **Ownership** — every entity is created by a wallet, so `createdBy` gives **cryptographic authorship**. Curated intelligence is owned by the Guardian/DAO key; community entities are owned by the reporter's wallet. **Writes are author-scoped (only the owner updates/deletes); reads are permissionless.** This is exactly the trust model a shared threat DB needs — and it powers our in-app "Why we flagged this / who reported it" provenance.

### 4. Why Arkiv, not a plain database?
- **Composability** — the exploit + spender-reputation DB-Chain is readable by *any* wallet or dApp. Threat intel becomes a shared public good, not a silo. Another security tool can query our `spender` verdicts today.
- **Permissionless contribution with provenance** — researchers write from their own wallet; `createdBy` proves *who* flagged something without a central gatekeeper. You get open contribution *and* accountability.
- **Native expiry = self-cleaning intel** — reputation and reports decay unless renewed; no cron jobs, no stale labels, no separate moderation DB.
- **Neutrality & tamper-evidence** — no single operator can silently rewrite or censor a risk classification. For a *security* product, "who can tamper with the threat DB" is a first-order question, and a decentralized DA layer answers it.
- **Portability** — the intelligence outlives our app. If Wallet Guardian disappears, the DB-Chain (and everyone reading it) persists.

A plain DB is faster to write but siloed, centrally mutable, and needs its own auth, moderation, and TTL machinery — and it gives zero cryptographic provenance or composability.

### 5. What stays OFF Arkiv?
- **Secrets** — private keys, seed phrases: never, anywhere.
- **A user's holdings & approval list** — never published. A wallet's exposure is private and user-specific, not shared intelligence.
- **Live chain reads** — balances, current allowances, event logs: fetched from RPC at scan time (real-time, user-specific).
- **Prices** — DefiLlama, ephemeral.
- **Large blobs / media** — store a URL or hash on Arkiv, not the bytes.
- **User scan snapshots (Risk Monitor)** — kept in local storage by default for privacy; *if* a user opts into cross-device sync, they'd be minimal, **user-owned** (`ownedBy` the user), short-TTL (`fromDays(7)`, extended on re-scan) entities — a clean showcase of Arkiv's ephemeral, owner-scoped storage, but off by default.

**The line:** shared + curated + composable → Arkiv. User-specific + real-time + private + ephemeral → off Arkiv (RPC + local store).

## Tech
- **Backend:** Node.js + Express, `ethers` v6 (EVM), `@solana/web3.js` (Solana). All external calls are server-side proxies (no CORS, no exposed keys).
- **Data (keyless):** public RPCs per chain, DefiLlama for prices, delegate.cash v2 registry for delegations, Jupiter token list for Solana metadata.
- **Arkiv:** `@arkiv-network/sdk` adapter behind a `DbChain` interface.
- **Frontend:** dependency-light vanilla JS + inline SVG; wallet connect via EIP-6963 (multi-wallet) + Solana provider detection + mobile deep-links.
- **Persistence:** SQLite (via the platform's DB API) for the Risk Monitor watchlist, alerts, and scan snapshots.

## Architecture highlight
Everything on-chain runs server-side; the browser only ever calls relative API routes. RPC providers are pooled and pinned with hard timeouts, so scans are bounded and never storm a node.

---

## Demo
- **Live app:** https://build-09bde00a7f107c4fb75cfe3c.emblem.build/pub/main/wallet-guardian/
- **Video:** [add link]
- Try **View demo wallet** for the full experience (exposure, grouped recommendations, confidence + provenance, exploit cases, delegations, sandbox), or connect a wallet for a live multi-chain scan + real revoke.

## Roadmap
1. **Live Arkiv DB-Chain** — seed exploits on-chain and open **community-contributed** patterns (permissionless, author-scoped writes) the moment the Sept-2026 testnet opens.
2. **Approved-transfer detection & history** — has a spender actually used your approval? (needs an indexer/explorer key).
3. **Real-time exploit alerts** — wired to a live threat feed.
4. **Smart-account auto-revoke** — revoke-only session keys (ERC-7715) for hands-off protection.
5. **Transaction & signature simulation** — preview a dangerous approval before you sign.

## Team
[add name(s) / handles]
