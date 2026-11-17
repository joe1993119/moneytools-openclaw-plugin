// Calls the two MoneyTools checks and pays for them from the agent's own wallet.
// Before paying, the 402 quote is verified (exact scheme, USDC on Base, payTo = MoneyTools team wallet, amount <= the published price),
// the key payer signs only that verified requirement, and the signed authorization is checked against it again before it is sent.
// Spend is reserved against the daily cap before any payment starts, so parallel checks cannot exceed it.
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
const UA = "moneytools-openclaw-plugin/0.1.7";

export class CheckError extends Error { constructor(code, message) { super(message); this.code = code; } }

function decodeHeader(v) { try { return JSON.parse(Buffer.from(v, "base64").toString("utf8")); } catch { return null; } }
const usdUnits = (usd) => BigInt(Math.round(Number(usd) * 1e6));
const sameAddr = (a, b) => typeof a === "string" && a.toLowerCase() === b.toLowerCase();
/** Read and verify the MoneyTools 402 quote. Throws CheckError when it is not exactly what we publish. */
export function verifyQuote(res, body, maxUsd) {
  const pr = (res.headers.get("payment-required") && decodeHeader(res.headers.get("payment-required"))) || body;
  const a = Array.isArray(pr?.accepts) ? pr.accepts.find((x) => x?.network === BASE && x?.scheme === "exact") || pr.accepts[0] : null;
  if (!a) throw new CheckError("bad_quote", "could not read the MoneyTools 402 quote");
  const amount = String(a.amount ?? a.maxAmountRequired ?? "");
  if (a.scheme !== "exact") throw new CheckError("bad_quote", "MoneyTools quote is not an exact-scheme payment; not paying");
  if (a.network !== BASE || !sameAddr(a.asset, USDC_BASE)) throw new CheckError("bad_quote", "MoneyTools quote is not USDC on Base; not paying");
  if (!sameAddr(a.payTo, MONEYTOOLS_PAY_TO)) throw new CheckError("bad_quote", "MoneyTools quote payTo is not the MoneyTools wallet; not paying");
  if (!/^\d+$/.test(amount) || BigInt(amount) <= 0n || BigInt(amount) > usdUnits(maxUsd)) throw new CheckError("over_price", `MoneyTools quoted ${Number(amount) / 1e6} USDC, above the ${maxUsd} USDC cap; not paying`);
  return { amountUsd: Number(amount) / 1e6, amountUnits: amount, accept: a, paymentRequired: pr };
}

/** Check a signed x402 payment against the verified quote before it leaves the process. Throws CheckError on any mismatch. */
export function verifySignedPayment(payload, quote, maxUsd, now = () => Date.now()) {
  const fail = (why) => { throw new CheckError("bad_payment", `signed payment does not match the verified MoneyTools quote (${why}); not sending`); };
  const acc = payload?.accepted; const auth = payload?.payload?.authorization;
  if (!acc || !auth) fail("no exact-scheme authorization");
  if (payload.x402Version !== 2) fail("x402 version");
  if (acc.scheme !== "exact" || acc.network !== BASE) fail("scheme/network");
  if (!sameAddr(acc.asset, USDC_BASE)) fail("asset");
  if (!sameAddr(acc.payTo, MONEYTOOLS_PAY_TO) || !sameAddr(auth.to, MONEYTOOLS_PAY_TO)) fail("payTo");
  if (String(acc.amount) !== quote.amountUnits || !/^\d+$/.test(String(auth.value)) || BigInt(auth.value) !== BigInt(quote.amountUnits)) fail("amount");
  if (BigInt(auth.value) > usdUnits(maxUsd)) fail("amount above cap");
  const validBefore = Number(auth.validBefore); const maxWindow = Number(quote.accept.maxTimeoutSeconds || 300) + 120;
  if (!Number.isFinite(validBefore) || validBefore > Math.floor(now() / 1000) + maxWindow) fail("authorization window");
  return true;
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

async function payWithKey(url, quote, maxUsd, payer, env, deps) {
  let mods;
  try { mods = deps.x402 || { fetch: await import("@x402/fetch"), evm: await import("@x402/evm/exact/client"), accounts: await import("viem/accounts") }; }
  catch { throw new CheckError("payer_unavailable", "@x402/fetch, @x402/evm and viem are needed for key payments"); }
  if (quote.paymentRequired?.x402Version !== 2) throw new CheckError("bad_quote", "MoneyTools quote is not x402 v2; not paying");
  const account = mods.accounts.privateKeyToAccount(env[payer.keyEnv].trim());
  const client = new mods.fetch.x402Client(); mods.evm.registerExactEvmScheme(client, { signer: account });
  const http = new mods.fetch.x402HTTPClient(client);
  // Sign only the requirement we verified; never let the client pick another one.
  const payload = await http.createPaymentPayload({ ...quote.paymentRequired, accepts: [quote.accept] });
  verifySignedPayment(payload, quote, maxUsd, deps.now);
  // One paid request, no automatic retry: a second 402 is treated as a failed (uncharged) check.
  return deps.fetch(url, { headers: { accept: "application/json", "user-agent": UA, ...http.encodePaymentSignatureHeader(payload) } });
}
/** Run `npx -y agentcash@<pinned> fetch <url> --format json ...`; AgentCash signs with its own wallet. */
/** AgentCash signs inside its own process; it is limited to x402 on Base and to maxUsd per request (--max-amount). */
export function runAgentcash(url, { timeoutMs = 60000, spawnFn = spawn, maxUsd } = {}) {
  return new Promise((resolve, reject) => {
    if (!(Number(maxUsd) > 0)) return reject(new CheckError("payer_failed", "no price cap for AgentCash; not paying"));
    const p = spawnFn("npx", ["-y", `agentcash@${AGENTCASH_VERSION}`, "fetch", url, "--format", "json", "--payment-protocol", "x402", "--payment-network", "base", "--max-amount", String(maxUsd)], { stdio: ["ignore", "pipe", "pipe"], env: process.env });
    let out = ""; const t = setTimeout(() => { try { p.kill("SIGTERM"); } catch {} reject(new CheckError("timeout", "AgentCash timed out")); }, timeoutMs);
    p.stdout.on("data", (d) => { out += d; if (out.length > 2e6) p.kill("SIGTERM"); });
    p.on("error", (e) => { clearTimeout(t); reject(new CheckError("payer_unavailable", `could not start AgentCash: ${e.message}`)); });
    p.on("close", () => { clearTimeout(t); let j; try { j = JSON.parse(out); } catch { return reject(new CheckError("payer_failed", "AgentCash returned no JSON")); }
      if (j?.success === true && j.data && typeof j.data === "object") return resolve(j.data);
      reject(new CheckError("payer_failed", "AgentCash payment failed")); }); // AgentCash's own error text is not passed on
  });
}

/** GET a MoneyTools check. Free tier first (unpaid request); on 402 verify the quote, then pay from the agent's wallet. */
export async function callCheck(url, { maxUsd, payer, env = process.env, fetch: f = globalThis.fetch, x402, agentcash = runAgentcash, budget, now, agentcashConfirmed = false, normalize = normalizeFor(url) } = {}) {
  const first = await f(url, { headers: { accept: "application/json", "user-agent": UA } });
  if (first.status === 200) return { data: normalize(await first.json().catch(() => null), false), paidUsd: 0 };
  if (first.status !== 402) { const j = await first.json().catch(() => ({})); const c = errCode(j?.error, first.status); throw new CheckError(c, `MoneyTools returned HTTP ${first.status} (${c})`); }
  const quote = verifyQuote(first, await first.json().catch(() => null), maxUsd);
  if (!payer || payer.kind === "none") throw new CheckError("no_payer", payer?.reason || "no wallet configured to pay for the check");
  // AgentCash signs in its own process, so its payment cannot be bound to the quote verified here. It never pays automatically:
  // only after the user confirms that one paid check (moneytools_* tool with payWithAgentcash: true, approved in OpenClaw).
  if (payer.kind === "agentcash" && !agentcashConfirmed) throw new CheckError("confirm_required", `this check costs ${quote.amountUsd} USDC after the free tier; AgentCash wallets are never charged automatically. To pay it, run the moneytools tool with payWithAgentcash: true and confirm`);
  // Reserve before any await so concurrent checks cannot both pass the cap; released if the payment does not complete.
  const hold = budget ? budget.reserve(quote.amountUsd) : null;
  if (budget && !hold) throw new CheckError("budget", `daily check budget reached (${budget.limitUsd} USDC)`);
  try {
    let data;
    if (payer.kind === "key") { const r = await payWithKey(url, quote, maxUsd, payer, env, { fetch: f, x402, now }); data = await r.json().catch(() => ({}));
      if (r.status !== 200) { const c = errCode(data?.error, r.status); throw new CheckError(c, `paid check failed with HTTP ${r.status} (${c}; not charged)`); } }
    else data = await agentcash(url, { maxUsd: quote.amountUsd });
    hold?.commit();
    return { data: normalize(data, true), paidUsd: quote.amountUsd };
  } catch (e) { hold?.release(); throw e; }
}

/** Only scheme, host, port and path of a target URL are sent to MoneyTools: user info, query string and fragment are dropped. */
export function sanitizeTargetUrl(target) {
  let u; try { u = new URL(String(target).trim()); } catch { throw new CheckError("bad_url", "not a valid URL"); }
  if (!/^https?:$/.test(u.protocol)) throw new CheckError("bad_url", "only http(s) URLs can be prechecked");
  u.username = ""; u.password = ""; u.search = ""; u.hash = ""; return u.toString();
}
// ---- Response validation: only allowlisted, typed fields of the MoneyTools responses reach decisions, logs or the model. ----
// Free text from upstream (summary, headline, flag details, labels, names) is dropped; short summaries are rebuilt locally from codes.
const CODE = /^[a-z0-9_]{1,64}$/;
const errCode = (c, status) => (typeof c === "string" && CODE.test(c) ? c : `http_${status}`);
const codes = (a, max = 20) => (Array.isArray(a) ? a.filter((x) => typeof x === "string" && CODE.test(x)).slice(0, max) : []);
const int = (x, lo, hi) => (Number.isInteger(x) && x >= lo && x <= hi ? x : null);
const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
function badResponse(paid, why) { const e = new CheckError("bad_response", `MoneyTools returned an unexpected response (${why})${paid ? "; the check was paid but its result was not used" : ""}`); e.charged = !!paid; return e; }
const PRECHECK_VERDICTS = ["ok", "warn", "block", "not_402"];
/** Pay precheck response -> { verdict, riskScore, summary, reasons, warnings, recommendedOption, options } */
export function normalizePrecheck(raw, paid = false) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw badResponse(paid, "not an object");
  if (!PRECHECK_VERDICTS.includes(raw.verdict)) throw badResponse(paid, "verdict");
  const riskScore = raw.riskScore === null ? null : int(raw.riskScore, 0, 100); if (raw.riskScore !== null && riskScore === null) throw badResponse(paid, "riskScore");
  const reasons = codes(raw.reasons), warnings = codes(raw.warnings);
  const options = (Array.isArray(raw.options) ? raw.options.slice(0, 20) : []).filter((o) => o && typeof o === "object").map((o) => ({
    index: int(o.index, 0, 19), valid: o.valid === true,
    network: typeof o.network === "string" && /^[a-z0-9:_-]{1,40}$/i.test(o.network) ? o.network : null,
    payTo: typeof o.payTo === "string" && ADDR_RE.test(o.payTo) ? o.payTo : null,
    amountAtomic: typeof o.amountAtomic === "string" && /^\d{1,40}$/.test(o.amountAtomic) ? o.amountAtomic : null,
    asset: typeof o.asset === "string" && ADDR_RE.test(o.asset) ? o.asset : null,
    sanctioned: o.sanctions?.hit === true, errors: codes(o.errors, 10), warnings: codes(o.warnings, 10) }));
  const summary = { ok: "payment requirements look well-formed; payTo not on the OFAC SDN snapshot", warn: `payable, but check warnings: ${warnings.join(", ") || "see warnings"}`,
    block: `do not pay: ${reasons.join(", ") || "seller terms failed the check"}`, not_402: "the URL did not answer with an x402 402" }[raw.verdict];
  return { verdict: raw.verdict, riskScore, summary, reasons, warnings, recommendedOption: raw.recommendedOption === null ? null : int(raw.recommendedOption, 0, 19), options };
}
const LEVELS = ["minimal", "low", "medium", "high", "critical"], SEVS = ["low", "medium", "high", "critical"];
/** Wallet Risk Card response -> { address, chain, riskScore, grade, level, sanctioned, headline, flags, approvals } */
export function normalizeWalletRisk(raw, paid = false) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw badResponse(paid, "not an object");
  const riskScore = int(raw.riskScore, 0, 100); if (riskScore === null) throw badResponse(paid, "riskScore");
  if (!LEVELS.includes(raw.level)) throw badResponse(paid, "level");
  if (typeof raw.grade !== "string" || !/^[A-F]$/.test(raw.grade)) throw badResponse(paid, "grade");
  if (typeof raw.sanctioned !== "boolean") throw badResponse(paid, "sanctioned");
  const flags = (Array.isArray(raw.flags) ? raw.flags : []).filter((f) => f && typeof f.code === "string" && CODE.test(f.code) && SEVS.includes(f.severity)).slice(0, 20).map((f) => ({ code: f.code, severity: f.severity }));
  const ap = raw.approvals && typeof raw.approvals === "object" && !raw.approvals.error ? raw.approvals : null;
  const approvals = ap ? { open: int(ap.open, 0, 1e6), unlimited: int(ap.unlimited, 0, 1e6), unknownSpender: int(ap.unknownSpender, 0, 1e6), toSanctionedSpender: int(ap.toSanctionedSpender, 0, 1e6) } : null;
  const headline = raw.sanctioned ? "Do not transact: address is on the OFAC SDN list." : flags.length ? `Risk ${raw.level} (${riskScore}/100): ${flags.slice(0, 3).map((f) => f.code.replace(/_/g, " ")).join("; ")}.` : "No risk flags found in the checks run.";
  return { address: typeof raw.address === "string" && ADDR_RE.test(raw.address) ? raw.address : null, chain: typeof raw.chain === "string" && /^[a-z]{2,20}$/.test(raw.chain) ? raw.chain : null,
    riskScore, grade: raw.grade, level: raw.level, sanctioned: raw.sanctioned, headline, flags, approvals };
}
export function normalizeFor(url) { return /\/v1\/wallet-risk\b/.test(String(url)) ? normalizeWalletRisk : /\/v1\/precheck\b/.test(String(url)) ? normalizePrecheck : () => { throw new CheckError("bad_url", "not a MoneyTools check URL"); }; }

export const precheckUrl = (target, method = "GET") => `${PRECHECK_URL}?url=${encodeURIComponent(sanitizeTargetUrl(target))}&method=${encodeURIComponent(method)}`;
export const walletRiskUrl = (address, chain = "base") => `${WALLET_RISK_URL}?address=${encodeURIComponent(address)}&chain=${encodeURIComponent(chain)}`;

/** Per-process UTC-day spend cap for the plugin's own checks. reserve() is synchronous (atomic in the event loop): a reservation counts toward the cap
 *  from the moment it is made, is kept by commit() and given back by release() when the payment does not complete. */
export function makeBudget(limitUsd, now = () => Date.now()) {
  const cap = usdUnits(limitUsd); let day = "", units = 0n;
  const roll = () => { const d = new Date(now()).toISOString().slice(0, 10); if (d !== day) { day = d; units = 0n; } return day; };
  return {
    limitUsd,
    canSpend(x) { roll(); return units + usdUnits(x) <= cap; },
    reserve(x) {
      const d = roll(); const amt = usdUnits(x); if (amt <= 0n || units + amt > cap) return null;
      units += amt; let done = false;
      return { commit() { done = true; }, release() { if (done) return; done = true; if (roll() === d) units -= amt; } };
    },
    get spentUsd() { roll(); return Number(units) / 1e6; },
  };
}
