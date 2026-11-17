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
  return approval(`Unchecked: ${what}`, `${msg}.${e.charged ? "" : " Nothing was charged for the check."} Continue without it?`, "warning");
}

/** Decision for a precheck result (https://api.moneytools.dev/v1/precheck). */
export function decidePrecheck(cfg, url, r) {
  // r is a normalized response (codes + locally built summary only).
  const v = String(r?.verdict || "").toLowerCase(); const why = [r?.summary].filter(Boolean).join("; ").slice(0, 600);
  if (v === "ok") return undefined;
  if (v === "block") return { block: true, blockReason: `MoneyTools pay precheck blocked this payment to ${url}: ${why || "seller terms failed the check"}` };
  if (v === "warn") return cfg.onPrecheckWarn === "allow" ? undefined : cfg.onPrecheckWarn === "block" ? { block: true, blockReason: `MoneyTools pay precheck warned: ${why}` } : approval("Pay precheck warning", `MoneyTools pay precheck flagged ${url}: ${why || "see warnings"}. Pay anyway?`);
  if (v === "not_402") return approval("Not an x402 seller", `MoneyTools pay precheck: ${url} did not answer with a valid x402 402. Continue?`, "info");
  return undefined;
}
/** Decision for a Wallet Risk Card (https://tools.moneytools.dev/v1/wallet-risk) on the approval spender. */
export function decideRisk(cfg, a, card) {
  const level = String(card?.level || "").toLowerCase(); const head = `${card?.headline || `risk ${card?.riskScore ?? "?"}/100`} (grade ${card?.grade ?? "?"})`;
  const what = `${a.unlimited ? "an UNLIMITED " : a.ambiguousZero ? "a zero-amount / token #0 " : "a "}${a.fn}${a.amount !== undefined && !a.unlimited && !a.ambiguousZero ? ` of ${a.amount}` : ""} to spender ${a.spender}${a.token ? ` (token ${a.token})` : ""} on ${a.chain}`;
  // approve(spender, 0) may be an ERC-20 revoke or an ERC-721 approval of token #0: never silently allowed for a risky spender, never auto-blocked either (it may be a revoke).
  // Applies only to this exact zero-amount operation; any positive or unlimited grant in the same call is judged by the rules below.
  if (a.ambiguousZero === true && !a.unlimited && (card?.sanctioned === true || ["high", "critical", "medium"].includes(level))) return approval(card?.sanctioned ? "Sanctioned spender" : "Check this spender", `Wallet Risk Card for approve(${a.spender}, 0) on ${a.chain}: ${card?.sanctioned ? "spender is on the OFAC SDN list; " : ""}${head}. This is either an ERC-20 revoke (safe) or an ERC-721 approval of token #0 (grants that NFT). Continue?`, card?.sanctioned || level !== "medium" ? "critical" : "warning");
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
  // confirmed = the user approved this one paid check in OpenClaw; only then may an AgentCash wallet pay.
  const agentcashPayer = () => resolvePayer({ ...cfg, payer: "agentcash" }, env, deps.fileExists);
  const run = (url, maxUsd, confirmed = false) => callCheck(url, { maxUsd, payer: confirmed ? agentcashPayer() : payer(), agentcashConfirmed: confirmed, env, fetch: deps.fetch || globalThis.fetch, x402: deps.x402, agentcash: deps.agentcash, budget, now: deps.now });
  const precheck = async (target, method, { agentcashConfirmed = false } = {}) => { const t = sanitizeTargetUrl(target); return cached(`p:${method}:${t}${agentcashConfirmed ? ":ac" : ""}`, () => run(precheckUrl(t, method), PRICES.precheck, agentcashConfirmed)); };
  const walletRisk = (address, chain, { agentcashConfirmed = false } = {}) => cached(`w:${chain}:${address.toLowerCase()}${agentcashConfirmed ? ":ac" : ""}`, () => run(walletRiskUrl(address, chain), PRICES.walletRisk, agentcashConfirmed));

  // One-time user confirmations for AgentCash-paid checks, recorded only when OpenClaw reports "allow-once" for that tool call.
  const grants = new Map(); const GRANT_MS = 120000;
  const grantKey = (name, params, id) => id ? `id:${id}` : `p:${name}:${JSON.stringify(params)}`;
  function takeGrant(name, params, id) {
    for (const k of [grantKey(name, params, id), grantKey(name, params, null)]) { const g = grants.get(k); if (g) { grants.delete(k); if (now() <= g) return true; } }
    return false;
  }

  async function beforeToolCall(event, ctx = {}) {
    const name = event?.toolName || ctx.toolName; const params = event?.params || {}; const opts = { paymentToolPattern: cfg.pattern, defaultChain: cfg.defaultChain, toolKind: event?.toolKind || ctx.toolKind };
    if (/^moneytools_(pay_precheck|wallet_risk)$/.test(name || "") && params.payWithAgentcash === true) {
      const price = name === "moneytools_wallet_risk" ? PRICES.walletRisk : PRICES.precheck; const id = event?.toolCallId || ctx.toolCallId; const key = grantKey(name, params, id);
      const subject = name === "moneytools_wallet_risk" ? `Wallet Risk Card for ${params.address}` : `pay precheck for ${(() => { try { return sanitizeTargetUrl(params.url); } catch { return "an invalid URL"; } })()}`;
      return { requireApproval: { title: "Pay for a MoneyTools check with AgentCash", description: `Pay up to ${price} USDC on Base from your AgentCash wallet for one ${subject}? AgentCash signs the payment itself (limited to x402 on Base and ${price} USDC). Nothing is paid if you deny.`, severity: "warning", timeoutMs: GRANT_MS, allowedDecisions: ["allow-once", "deny"],
        onResolution: (d) => { if (d === "allow-once") grants.set(key, now() + GRANT_MS); } } };
    }
    const parts = [];
    if (cfg.checkApprovals) {
      const { approvals, problems } = detectApprovals(name, params, opts);
      // One risk lookup per spender (cached, concurrent lookups shared); every approval is then judged on its own.
      parts.push(...await Promise.all(approvals.map(async (a) => {
        try { const { data, paidUsd } = await walletRisk(a.spender, a.chain); log.info?.(`[${PLUGIN_ID}] wallet-risk ${a.spender} ${a.chain}: ${data?.level} (${paidUsd ? fmtUsd(paidUsd) : "free/cached"})`); return decideRisk(cfg, a, data); }
        catch (e) { return onError(cfg, `Wallet Risk Card for ${a.spender}`, e); } })));
      // Approval content that could not be decoded, or whose fields disagree, is never treated as screened.
      for (const p of problems) parts.push(onError(cfg, "approval screening", new Error(p)));
    }
    if (cfg.precheckPayments) { const p = detectX402Payment(name, params, opts);
      if (p) { try { const { data, paidUsd } = await precheck(p.url, p.method); log.info?.(`[${PLUGIN_ID}] precheck ${sanitizeTargetUrl(p.url)}: ${data?.verdict} (${paidUsd ? fmtUsd(paidUsd) : "free/cached"})`); parts.push(decidePrecheck(cfg, p.url, data));
          // The query string is never sent to MoneyTools, so its payment terms were not screened: follow onCheckError (ask by default).
          if (p.hasQuery) parts.push(onError(cfg, "pay precheck for the query string", new CheckError("query_not_checked", `the precheck covered only the base path ${p.url}; the query string was not sent to MoneyTools, so payment terms that depend on it were not screened`))); }
        catch (e) { parts.push(onError(cfg, "pay precheck", e)); } } }
    return combineDecisions(parts);
  }
  return { cfg, budget, beforeToolCall, precheck, walletRisk, payer, takeGrant };
}

// Tool results carry only the normalized, allowlisted fields (see normalizePrecheck / normalizeWalletRisk) and our own error codes.
const NOTE = "Fields validated and normalized by the MoneyTools Guard plugin; upstream free text is not included.";
const text = (o) => ({ content: [{ type: "text", text: JSON.stringify(o, null, 2) }], details: o });
const errOut = (e) => text({ error: typeof e?.code === "string" && /^[a-z0-9_]{1,64}$/.test(e.code) ? e.code : "error", message: e instanceof CheckError ? e.message : "check failed", charged: !!e?.charged });
export function toolDefs(guard, Type) {
  const AC = (Type) => Type.Optional(Type.Boolean({ description: "Pay this one check from your AgentCash wallet after the free tier. OpenClaw asks the user to confirm first; without that confirmation nothing is paid." }));
  const confirmed = (name, p, id) => { if (p.payWithAgentcash !== true) return false; if (!guard.takeGrant(name, p, id)) throw new CheckError("confirm_required", "payWithAgentcash needs the user's confirmation in OpenClaw for this call; nothing was paid"); return true; };
  return [
    { name: "moneytools_pay_precheck", description: `Check an x402 seller URL before paying: validates its 402 terms (network, amount, asset, payTo) and screens payTo against the OFAC SDN list. Free daily tier, then ${PRICES.precheck} USDC on Base, paid from your own wallet (AgentCash only with payWithAgentcash and your confirmation). Failed checks are not charged.`,
      parameters: Type.Object({ url: Type.String({ description: "x402 endpoint you plan to pay" }), method: Type.Optional(Type.String({ description: "HTTP method of the paid call (default GET)" })), payWithAgentcash: AC(Type) }),
      async execute(_id, p) { try { const ac = confirmed("moneytools_pay_precheck", p, _id); const r = await guard.precheck(p.url, (p.method || "GET").toUpperCase(), { agentcashConfirmed: ac });
        const q = (() => { try { return new URL(String(p.url).trim()).search.length > 1; } catch { return false; } })();
        return text({ ...r.data, paidUsd: r.paidUsd, coverage: q ? "base path only: the query string was not sent or checked; payment terms that depend on it were not screened" : "full path", note: NOTE }); } catch (e) { return errOut(e); } } },
    { name: "moneytools_wallet_risk", description: `Wallet Risk Card for an EVM address or ENS name before you pay, trust or approve it: 0-100 risk score, grade A-F, OFAC SDN match, address checks, open approvals. ${PRICES.walletRisk} USDC on Base, paid from your own wallet (AgentCash only with payWithAgentcash and your confirmation). Failed checks are not charged.`,
      parameters: Type.Object({ address: Type.String({ description: "0x address or ENS name" }), chain: Type.Optional(Type.String({ description: `one of ${[...new Set(Object.values(CHAINS))].join(", ")} (default base)` })), payWithAgentcash: AC(Type) }),
      async execute(_id, p) { try { const ac = confirmed("moneytools_wallet_risk", p, _id); const r = await guard.walletRisk(p.address, CHAINS[String(p.chain || "base").toLowerCase()] || "base", { agentcashConfirmed: ac }); return text({ ...r.data, paidUsd: r.paidUsd, note: NOTE }); } catch (e) { return errOut(e); } } },
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
