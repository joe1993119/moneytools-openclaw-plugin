// Host-free plugin logic: config, decisions, the before_tool_call handler and the two explicit tools.
import { detectX402Payment, detectApprovals, DEFAULT_PAYMENT_TOOL_PATTERN, CHAINS } from "./detect.js";
import { callCheck, resolvePayer, makeBudget, precheckUrl, walletRiskUrl, sanitizeTargetUrl, PRICES, CheckError } from "./checks.js";

export const PLUGIN_ID = "moneytools-guard";
export const DEFAULTS = { autoPay: false, payer: "auto", privateKeyEnv: "X402_PRIVATE_KEY", dailyBudgetUsd: 0.25, precheckPayments: true, checkApprovals: true,
  onPrecheckWarn: "approve", onHighRisk: "block", onMediumRisk: "approve", onCheckError: "approve", defaultChain: "base", paymentToolPattern: "", cacheMinutes: 10 };

export function readConfig(raw = {}) {
  const c = { ...DEFAULTS, ...(raw && typeof raw === "object" ? raw : {}) };
  c.dailyBudgetUsd = Math.max(0, Math.min(Number(c.dailyBudgetUsd) || 0, 5));
  let pattern = DEFAULT_PAYMENT_TOOL_PATTERN; if (c.paymentToolPattern) { try { pattern = new RegExp(c.paymentToolPattern, "i"); } catch {} }
  c.pattern = pattern; return c;
}

const fmtUsd = (x) => `${Number(x).toFixed(3).replace(/0+$/, "").replace(/\.$/, "")} USDC`;
function approval(title, description, severity = "warning") { return { requireApproval: { title, description: description.slice(0, 1500), severity, timeoutMs: 120000, allowedDecisions: ["allow-once", "deny"] } }; }
function onError(cfg, what, e) {
  const msg = `MoneyTools ${what} did not run: ${e.message}`;
  if (cfg.onCheckError === "allow") return undefined;
  if (cfg.onCheckError === "block") return { block: true, blockReason: msg };
  return approval(`Unchecked: ${what}`, `${msg}. Nothing was charged for the check. Continue without it?`, "warning");
}

/** Decision for a precheck result (https://api.moneytools.dev/v1/precheck). */
export function decidePrecheck(cfg, url, r) {
  const v = String(r?.verdict || "").toLowerCase(); const why = [r?.summary, ...(r?.reasons || []), ...(r?.warnings || [])].filter(Boolean).join("; ").slice(0, 600);
  if (v === "ok") return undefined;
  if (v === "block") return { block: true, blockReason: `MoneyTools pay precheck blocked this payment to ${url}: ${why || "seller terms failed the check"}` };
  if (v === "warn") return cfg.onPrecheckWarn === "allow" ? undefined : cfg.onPrecheckWarn === "block" ? { block: true, blockReason: `MoneyTools pay precheck warned: ${why}` } : approval("Pay precheck warning", `MoneyTools pay precheck flagged ${url}: ${why || "see warnings"}. Pay anyway?`);
  if (v === "not_402") return approval("Not an x402 seller", `MoneyTools pay precheck: ${url} did not answer with a valid x402 402. Continue?`, "info");
  return undefined;
}
/** Decision for a Wallet Risk Card (https://tools.moneytools.dev/v1/wallet-risk) on the approval spender. */
export function decideRisk(cfg, a, card) {
  const level = String(card?.level || "").toLowerCase(); const head = `${card?.headline || `risk ${card?.riskScore ?? "?"}/100`} (grade ${card?.grade ?? "?"})`;
  const what = `${a.unlimited ? "an UNLIMITED " : "a "}${a.fn} to spender ${a.spender} on ${a.chain}`;
  if (card?.sanctioned === true) return { block: true, blockReason: `MoneyTools Wallet Risk Card: spender ${a.spender} is on the OFAC SDN list. Blocked ${what}.` };
  if (level === "high" || level === "critical") return cfg.onHighRisk === "approve" ? approval("High-risk spender", `Wallet Risk Card for ${what}: ${head}. Approve anyway?`, "critical") : { block: true, blockReason: `MoneyTools Wallet Risk Card: high risk for ${what}: ${head}.` };
  if (level === "medium") return cfg.onMediumRisk === "allow" ? undefined : cfg.onMediumRisk === "block" ? { block: true, blockReason: `MoneyTools Wallet Risk Card: medium risk for ${what}: ${head}.` } : approval("Check this spender", `Wallet Risk Card for ${what}: ${head}. Approve?`, "warning");
  return undefined;
}

const SEV = { info: 0, warning: 1, critical: 2 };
/** Strict combine: any block blocks the whole call; otherwise any approval request asks once with every reason; allow only when every part allowed. */
export function combineDecisions(decisions) {
  const ds = decisions.filter(Boolean);
  const blocks = ds.filter((d) => d.block); if (blocks.length) return { block: true, blockReason: blocks.map((d) => d.blockReason).join(" | ").slice(0, 1500) };
  const asks = ds.filter((d) => d.requireApproval); if (!asks.length) return undefined;
  if (asks.length === 1) return asks[0];
  const sev = asks.map((d) => d.requireApproval.severity).reduce((a, b) => (SEV[b] > SEV[a] ? b : a), "info");
  return approval(`${asks.length} checks need your OK`, asks.map((d, i) => `${i + 1}. ${d.requireApproval.title}: ${d.requireApproval.description}`).join("\n"), sev);
}

export function createGuard(rawCfg, deps = {}) {
  const cfg = readConfig(rawCfg); const env = deps.env || process.env; const log = deps.logger || { info() {}, warn() {} };
  const budget = makeBudget(cfg.dailyBudgetUsd, deps.now); const cache = new Map(); const ttl = cfg.cacheMinutes * 60000; const now = deps.now || (() => Date.now());
  const payer = () => (cfg.autoPay ? resolvePayer(cfg, env, deps.fileExists) : { kind: "none", reason: "autoPay is off (free tier only)" });
  const inflight = new Map();
  // Results are cached, and identical checks already running share one request (and at most one payment).
  async function cached(key, fn) {
    const hit = cache.get(key); if (hit && now() - hit.at < ttl) return hit.v;
    if (inflight.has(key)) return inflight.get(key);
    const p = (async () => { try { const v = await fn(); cache.set(key, { v, at: now() }); if (cache.size > 500) cache.delete(cache.keys().next().value); return v; } finally { inflight.delete(key); } })();
    inflight.set(key, p); return p;
  }
  const run = (url, maxUsd) => callCheck(url, { maxUsd, payer: payer(), env, fetch: deps.fetch || globalThis.fetch, x402: deps.x402, agentcash: deps.agentcash, budget, now: deps.now });
  const precheck = async (target, method) => { const t = sanitizeTargetUrl(target); return cached(`p:${method}:${t}`, () => run(precheckUrl(t, method), PRICES.precheck)); };
  const walletRisk = (address, chain) => cached(`w:${chain}:${address.toLowerCase()}`, () => run(walletRiskUrl(address, chain), PRICES.walletRisk));

  async function beforeToolCall(event, ctx = {}) {
    const name = event?.toolName || ctx.toolName; const params = event?.params || {}; const opts = { paymentToolPattern: cfg.pattern, defaultChain: cfg.defaultChain, toolKind: event?.toolKind || ctx.toolKind };
    const parts = [];
    if (cfg.checkApprovals) {
      const { approvals, problems } = detectApprovals(name, params, opts);
      // Every approval in the call is screened (in parallel; the budget reservation keeps spend under the cap).
      parts.push(...await Promise.all(approvals.map(async (a) => {
        try { const { data, paidUsd } = await walletRisk(a.spender, a.chain); log.info?.(`[${PLUGIN_ID}] wallet-risk ${a.spender} ${a.chain}: ${data?.level} (${paidUsd ? fmtUsd(paidUsd) : "free/cached"})`); return decideRisk(cfg, a, data); }
        catch (e) { return onError(cfg, `Wallet Risk Card for ${a.spender}`, e); } })));
      // Approval content that could not be decoded, or whose fields disagree, is never treated as screened.
      for (const p of problems) parts.push(onError(cfg, "approval screening", new Error(p)));
    }
    if (cfg.precheckPayments) { const p = detectX402Payment(name, params, opts);
      if (p) { try { const { data, paidUsd } = await precheck(p.url, p.method); log.info?.(`[${PLUGIN_ID}] precheck ${sanitizeTargetUrl(p.url)}: ${data?.verdict} (${paidUsd ? fmtUsd(paidUsd) : "free/cached"})`); parts.push(decidePrecheck(cfg, p.url, data)); }
        catch (e) { parts.push(onError(cfg, "pay precheck", e)); } } }
    return combineDecisions(parts);
  }
  return { cfg, budget, beforeToolCall, precheck, walletRisk, payer };
}

const text = (o) => ({ content: [{ type: "text", text: JSON.stringify(o, null, 2) }], details: o });
export function toolDefs(guard, Type) {
  return [
    { name: "moneytools_pay_precheck", description: `Check an x402 seller URL before paying: validates its 402 terms (network, amount, asset, payTo) and screens payTo against the OFAC SDN list. Free daily tier, then ${PRICES.precheck} USDC on Base, paid from your own wallet. Failed checks are not charged.`,
      parameters: Type.Object({ url: Type.String({ description: "x402 endpoint you plan to pay" }), method: Type.Optional(Type.String({ description: "HTTP method of the paid call (default GET)" })) }),
      async execute(_id, p) { try { const r = await guard.precheck(p.url, (p.method || "GET").toUpperCase()); return text({ ...r.data, paidUsd: r.paidUsd }); } catch (e) { return text({ error: e.code || "error", message: e.message, charged: false }); } } },
    { name: "moneytools_wallet_risk", description: `Wallet Risk Card for an EVM address or ENS name before you pay, trust or approve it: 0-100 risk score, grade A-F, OFAC SDN match, address checks, open approvals. ${PRICES.walletRisk} USDC on Base, paid from your own wallet. Failed checks are not charged.`,
      parameters: Type.Object({ address: Type.String({ description: "0x address or ENS name" }), chain: Type.Optional(Type.String({ description: `one of ${[...new Set(Object.values(CHAINS))].join(", ")} (default base)` })) }),
      async execute(_id, p) { try { const r = await guard.walletRisk(p.address, CHAINS[String(p.chain || "base").toLowerCase()] || "base"); return text({ ...r.data, paidUsd: r.paidUsd }); } catch (e) { return text({ error: e.code || "error", message: e.message, charged: false }); } } },
  ];
}

/** register(api) body shared by the entry point and tests. */
export function registerGuard(api, Type, deps = {}) {
  const guard = createGuard(api.pluginConfig || {}, { logger: api.logger, ...deps });
  api.on("before_tool_call", (event, ctx) => guard.beforeToolCall(event, ctx), { priority: 60, timeoutMs: 90000 });
  for (const t of toolDefs(guard, Type)) api.registerTool(t);
  return guard;
}
export { CheckError };
