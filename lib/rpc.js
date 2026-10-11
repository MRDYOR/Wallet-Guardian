'use strict';

/*
 * Bounded, cached RPC providers.
 *
 * Why this exists: creating a fresh ethers.JsonRpcProvider per call makes ethers
 * re-detect the network (eth_chainId) every time and, on a rate-limited public
 * RPC, retry failed requests repeatedly. Under the monitor sweep that fanned out
 * to ~100 concurrent calls and pegged the host. We now:
 *   - reuse ONE provider per RPC URL (module-level cache)
 *   - pin the network (staticNetwork) so there is NO network-detection/retry
 *   - set a hard per-request timeout so a hung RPC fails fast instead of piling up
 */

const { ethers } = require('ethers');

const cache = new Map();

function getProvider(url, chainId) {
  const key = url || 'https://ethereum-rpc.publicnode.com';
  if (cache.has(key)) return cache.get(key);
  const req = new ethers.FetchRequest(key);
  req.timeout = 7000; // 7s hard cap per request — no infinite retries
  let net = null;
  try { if (chainId) net = ethers.Network.from(Number(chainId)); } catch (e) { net = null; }
  const provider = new ethers.JsonRpcProvider(req, net || undefined, {
    staticNetwork: net || true, // never re-detect the chain
    batchMaxCount: 3,
    polling: false,
  });
  cache.set(key, provider);
  return provider;
}

module.exports = { getProvider };
