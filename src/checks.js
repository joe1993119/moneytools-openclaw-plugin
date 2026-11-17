// Calls the two MoneyTools checks and pays for them from the agent's own wallet.
// Before paying, the 402 quote is verified: USDC on Base, payTo = MoneyTools team wallet, amount <= the published price.
// MoneyTools does not settle a payment when the check itself fails, so failed checks are not charged.
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const PRECHECK_URL = "https://api.moneytools.dev/v1/precheck";
export const WALLET_RISK_URL = "https://tools.moneytools.dev/v1/wallet-risk";
export const MONEYTOOLS_PAY_TO = "0x64eB63904Cf9688AC5B3087A72AcF9C31a273169";
export const USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
export const BASE = "eip155:8453";
export const PRICES = { precheck: 0.005, walletRisk: 0.02 };
export const AGENTCASH_VERSION = "0.17.1"; // pinned; never @latest
const UA = "moneytools-openclaw-plugin/0.1.1";

export class CheckError extends Error { constructor(code, message) { super(message); this.code = code; } }

function decodeHeader(v) { try { return JSON.parse(Buffer.from(v, "base64").toString("utf8")); } catch { return null; } }
/** Read and verify the MoneyTools 402 quote. Throws CheckError when it is not exactly what we publish. */
export function verifyQuote(res, body, maxUsd) {
  const pr = (res.headers.get("payment-required") && decodeHeader(res.headers.get("payment-required"))) || body;
  const a = Array.isArray(pr?.accepts) ? pr.accepts.find((x) => x?.network === BASE) || pr.accepts[0] : null;
  if (!a) throw new CheckError("bad_quote", "could not read the MoneyTools 402 quote");
  const amount = String(a.amount ?? a.maxAmountRequired ?? "");
  if (a.network !== BASE || String(a.asset || "").toLowerCase() !== USDC_BASE) throw new CheckError("bad_quote", "MoneyTools quote is not USDC on Base; not paying");
  if (String(a.payTo || "").toLowerCase() !== MONEYTOOLS_PAY_TO.toLowerCase()) throw new CheckError("bad_quote", "MoneyTools quote payTo is not the MoneyTools wallet; not paying");
  const usd = Number(amount) / 1e6;
  if (!/^\d+$/.test(amount) || !(usd > 0) || usd > maxUsd + 1e-9) throw new CheckError("over_price", `MoneyTools quoted ${usd} USDC, above the ${maxUsd} USDC cap; not paying`);
  return { amountUsd: usd, accept: a };
}

/** Which wallet pays: "key" (env X402_PRIVATE_KEY or the configured env var), "agentcash" (existing ~/.agentcash/wallet.json), or "none". Never reads the key file itself. */
export function resolvePayer(cfg = {}, env = process.env, fileExists = existsSync) {
  const want = cfg.payer || "auto"; const keyEnv = cfg.privateKeyEnv || "X402_PRIVATE_KEY";
  const hasKey = typeof env[keyEnv] === "string" && /^0x[0-9a-fA-F]{64}$/.test(env[keyEnv].trim());
  const acWallet = join(cfg.agentcashHome || homedir(), ".agentcash", "wallet.json");
  if (want === "none") return { kind: "none" };
  if (want === "key") return hasKey ? { kind: "key", keyEnv } : { kind: "none", reason: `${keyEnv} is not set` };
  if (want === "agentcash") return fileExists(acWallet) ? { kind: "agentcash" } : { kind: "none", reason: "no AgentCash wallet (~/.agentcash/wallet.json); run `npx agentcash onboard` first" };
  if (hasKey) return { kind: "key", keyEnv };
  if (fileExists(acWallet)) return { kind: "agentcash" };
  return { kind: "none", reason: `no payer: set ${keyEnv} or create an AgentCash wallet` };
}

async function payWithKey(url, payer, env, deps) {
  let mods;
  try { mods = deps.x402 || { fetch: await import("@x402/fetch"), evm: await import("@x402/evm/exact/client"), accounts: await import("viem/accounts") }; }
  catch { throw new CheckError("payer_unavailable", "@x402/fetch, @x402/evm and viem are needed for key payments"); }
  const account = mods.accounts.privateKeyToAccount(env[payer.keyEnv].trim());
  const client = new mods.fetch.x402Client(); mods.evm.registerExactEvmScheme(client, { signer: account });
  const paid = mods.fetch.wrapFetchWithPayment(deps.fetch, client);
  return paid(url, { headers: { accept: "application/json", "user-agent": UA } });
}
/** Run `npx -y agentcash@<pinned> fetch <url> --format json`; AgentCash signs with its own wallet. */
export function runAgentcash(url, { timeoutMs = 60000, spawnFn = spawn } = {}) {
  return new Promise((resolve, reject) => {
    const p = spawnFn("npx", ["-y", `agentcash@${AGENTCASH_VERSION}`, "fetch", url, "--format", "json"], { stdio: ["ignore", "pipe", "pipe"], env: process.env });
    let out = ""; const t = setTimeout(() => { try { p.kill("SIGTERM"); } catch {} reject(new CheckError("timeout", "AgentCash timed out")); }, timeoutMs);
    p.stdout.on("data", (d) => { out += d; if (out.length > 2e6) p.kill("SIGTERM"); });
    p.on("error", (e) => { clearTimeout(t); reject(new CheckError("payer_unavailable", `could not start AgentCash: ${e.message}`)); });
    p.on("close", () => { clearTimeout(t); let j; try { j = JSON.parse(out); } catch { return reject(new CheckError("payer_failed", "AgentCash returned no JSON")); }
      if (j?.success === true && j.data && typeof j.data === "object") return resolve(j.data);
      reject(new CheckError("payer_failed", String(j?.error?.message || j?.error || "AgentCash payment failed").slice(0, 200))); });
  });
}

/** GET a MoneyTools check. Free tier first (unpaid request); on 402 verify the quote, then pay from the agent's wallet. */
export async function callCheck(url, { maxUsd, payer, env = process.env, fetch: f = globalThis.fetch, x402, agentcash = runAgentcash, budget } = {}) {
  const first = await f(url, { headers: { accept: "application/json", "user-agent": UA } });
  if (first.status === 200) return { data: await first.json(), paidUsd: 0 };
  if (first.status !== 402) { const j = await first.json().catch(() => ({})); throw new CheckError(j.error || `http_${first.status}`, j.message || `MoneyTools returned HTTP ${first.status}`); }
  const quote = verifyQuote(first, await first.json().catch(() => null), maxUsd);
  if (!payer || payer.kind === "none") throw new CheckError("no_payer", payer?.reason || "no wallet configured to pay for the check");
  if (budget && !budget.canSpend(quote.amountUsd)) throw new CheckError("budget", `daily check budget reached (${budget.limitUsd} USDC)`);
  let data;
  if (payer.kind === "key") { const r = await payWithKey(url, payer, env, { fetch: f, x402 }); data = await r.json().catch(() => ({}));
    if (r.status !== 200) throw new CheckError(data.error || `http_${r.status}`, data.message || `paid check failed with HTTP ${r.status} (not charged)`); }
  else data = await agentcash(url);
  budget?.spend(quote.amountUsd);
  return { data, paidUsd: quote.amountUsd };
}

export const precheckUrl = (target, method = "GET") => `${PRECHECK_URL}?url=${encodeURIComponent(target)}&method=${encodeURIComponent(method)}`;
export const walletRiskUrl = (address, chain = "base") => `${WALLET_RISK_URL}?address=${encodeURIComponent(address)}&chain=${encodeURIComponent(chain)}`;

/** Per-process UTC-day spend cap for the plugin's own checks. */
export function makeBudget(limitUsd, now = () => Date.now()) {
  let day = "", spent = 0; const roll = () => { const d = new Date(now()).toISOString().slice(0, 10); if (d !== day) { day = d; spent = 0; } };
  return { limitUsd, canSpend(x) { roll(); return spent + x <= limitUsd + 1e-9; }, spend(x) { roll(); spent += x; }, get spentUsd() { roll(); return spent; } };
}
