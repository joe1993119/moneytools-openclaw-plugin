// Detect, from a tool call's name and params, (a) an x402 payment about to be made and (b) an ERC-20 / NFT / Permit2 approval about to be sent or signed.
// Pure functions, no I/O. Detection is heuristic and conservative: it only fires on clear signals.

const URL_KEYS = ["url", "endpoint", "resource", "resourceUrl", "resource_url", "uri", "target", "href"];
const PAY_HEADER = /^(payment-signature|x-payment)$/i;
const EXEC_TOOLS = /^(exec|bash|shell|sh|run|run_command|run_shell_command|terminal|command|code_mode_exec)$/i;
export const DEFAULT_PAYMENT_TOOL_PATTERN = /x402|agentcash|(^|[_.:\-])pay(ment)?s?([_.:\-]|$)|paid[_-]?fetch|fetch[_-]with[_-](auth|payment)|clawrouter|blockrun/i;

// approve(address,uint256) / increaseAllowance(address,uint256) / setApprovalForAll(address,bool) / Permit2 approve(address,address,uint160,uint48)
const SELECTORS = {
  "0x095ea7b3": { fn: "approve", spenderArg: 0, amountArg: 1 },
  "0x39509351": { fn: "increaseAllowance", spenderArg: 0, amountArg: 1 },
  "0xa22cb465": { fn: "setApprovalForAll", spenderArg: 0, boolArg: 1 },
  "0x87517c45": { fn: "permit2.approve", spenderArg: 1, amountArg: 2 },
};
const APPROVE_FN = /^(approve|increaseallowance|setapprovalforall|permit|permit2[._]?approve)$/i;
const PERMIT_TYPES = /^(permit|permitsingle|permitbatch|permittransferfrom|permitbatchtransferfrom)$/i;
const MAX_UINT256 = (1n << 256n) - 1n;
const ADDR = /^0x[0-9a-fA-F]{40}$/;

export const CHAINS = { base: "base", "8453": "base", "eip155:8453": "base", ethereum: "ethereum", mainnet: "ethereum", eth: "ethereum", "1": "ethereum", "eip155:1": "ethereum",
  arbitrum: "arbitrum", "arbitrum-one": "arbitrum", "42161": "arbitrum", "eip155:42161": "arbitrum", optimism: "optimism", op: "optimism", "10": "optimism", "eip155:10": "optimism",
  polygon: "polygon", matic: "polygon", "137": "polygon", "eip155:137": "polygon", bsc: "bsc", bnb: "bsc", "56": "bsc", "eip155:56": "bsc", avalanche: "avalanche", avax: "avalanche", "43114": "avalanche", "eip155:43114": "avalanche" };

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
function* walk(v, depth = 0, key = "") { if (depth > 6) return; yield [key, v]; if (Array.isArray(v)) { for (const x of v.slice(0, 50)) yield* walk(x, depth + 1, key); } else if (isObj(v)) { for (const [k, x] of Object.entries(v).slice(0, 100)) yield* walk(x, depth + 1, k); } }
// Returned URLs carry only scheme, host, port and path: user info, query string and fragment are dropped so they never reach logs or the check API.
export const stripUrl = (s) => { if (typeof s !== "string") return null; try { const u = new URL(s.trim()); if (!/^https?:$/.test(u.protocol)) return null; u.username = ""; u.password = ""; u.search = ""; u.hash = ""; return u.toString(); } catch { return null; } };
const httpUrl = stripUrl;

export function isOwnCheckUrl(url) { try { return /(^|\.)moneytools\.dev$/i.test(new URL(url).hostname); } catch { return false; } }

function findUrl(params) {
  for (const k of URL_KEYS) { const u = httpUrl(params?.[k]); if (u) return u; }
  for (const k of ["request", "input", "args", "arguments"]) if (isObj(params?.[k])) { const u = findUrl(params[k]); if (u) return u; }
  return null;
}
function hasPaymentHeader(params) {
  for (const [, v] of walk(params)) {
    if (isObj(v)) { for (const k of Object.keys(v)) if (PAY_HEADER.test(k)) return true; }
    if (typeof v === "string" && /^\s*(payment-signature|x-payment)\s*:/i.test(v)) return true;
  }
  return false;
}
function commandOf(params) { for (const k of ["command", "cmd", "script", "code", "input"]) if (typeof params?.[k] === "string") return params[k]; if (Array.isArray(params?.command)) return params.command.join(" "); return ""; }

/** Is this tool call about to pay an x402 endpoint? -> { url, method, via } | null */
export function detectX402Payment(toolName, params, opts = {}) {
  const name = String(toolName || ""); const pattern = opts.paymentToolPattern || DEFAULT_PAYMENT_TOOL_PATTERN;
  if (/^moneytools_/i.test(name)) return null;
  const method = String(params?.method || params?.httpMethod || "GET").toUpperCase();
  if (EXEC_TOOLS.test(name) || opts.toolKind === "code_mode_exec") {
    const cmd = commandOf(params);
    const m = /\bagentcash(?:@[\w.\-]+)?\s+(?:fetch|fetch-auth)\s+["']?(https?:\/\/[^\s"']+)/i.exec(cmd);
    if (m && !isOwnCheckUrl(m[1]) && stripUrl(m[1])) return { url: stripUrl(m[1]), method: /(?:-m|--method)\s+(POST|PUT|PATCH|DELETE)/i.exec(cmd)?.[1]?.toUpperCase() || "GET", via: "exec:agentcash" };
    if (/(payment-signature|x-payment)\s*:/i.test(cmd)) { const u = /(https?:\/\/[^\s"']+)/.exec(cmd)?.[1]; if (u && !isOwnCheckUrl(u) && stripUrl(u)) return { url: stripUrl(u), method: /-X\s+(POST|PUT|PATCH|DELETE)/i.exec(cmd)?.[1]?.toUpperCase() || "GET", via: "exec:payment-header" }; }
    return null;
  }
  const url = findUrl(params); if (!url || isOwnCheckUrl(url)) return null;
  if (hasPaymentHeader(params)) return { url, method, via: "payment-header" };
  if (pattern.test(name)) return { url, method, via: "tool-name" };
  return null;
}

function word(hex, i) { const w = hex.slice(10 + 64 * i, 10 + 64 * (i + 1)); return w.length === 64 ? w : null; }
function decodeCalldata(data) {
  if (typeof data !== "string" || !/^0x[0-9a-fA-F]{8}/.test(data)) return null;
  const sel = SELECTORS[data.slice(0, 10).toLowerCase()]; if (!sel) return null;
  const sw = word(data, sel.spenderArg); if (!sw) return null;
  const spender = "0x" + sw.slice(24);
  if (sel.boolArg !== undefined) { const b = word(data, sel.boolArg); if (!b || BigInt("0x" + b) === 0n) return null; return { fn: sel.fn, spender, unlimited: true }; }
  const aw = word(data, sel.amountArg); const amount = aw ? BigInt("0x" + aw) : null;
  if (sel.fn === "approve" && amount === 0n) return null; // approve(spender, 0) is a revoke
  const unlimited = amount !== null && (sel.fn === "permit2.approve" ? amount >= (1n << 160n) - 1n : amount >= MAX_UINT256 / 2n);
  return { fn: sel.fn, spender, amount: amount === null ? null : amount.toString(), unlimited };
}
function chainOf(params, fallback) {
  for (const [k, v] of walk(params)) if (/^(chain|chainid|chain_id|network|chainname)$/i.test(k) && (typeof v === "string" || typeof v === "number")) { const c = CHAINS[String(v).toLowerCase()]; if (c) return c; }
  return fallback;
}

/** Is this tool call about to grant a token approval (tx or Permit signature)? -> { spender, chain, fn, unlimited, via } | null */
export function detectApproval(toolName, params, opts = {}) {
  const name = String(toolName || ""); if (/^moneytools_/i.test(name)) return null;
  const chain = chainOf(params, opts.defaultChain || "base");
  for (const [, v] of walk(params)) { const d = decodeCalldata(v); if (d && ADDR.test(d.spender)) return { ...d, chain, via: "calldata" }; }
  for (const [, v] of walk(params)) {
    if (!isObj(v)) continue;
    const fn = v.functionName ?? v.function ?? v.method ?? v.action;
    if (typeof fn === "string" && APPROVE_FN.test(fn.replace(/\(.*$/, ""))) {
      const args = Array.isArray(v.args) ? v.args : Array.isArray(v.arguments) ? v.arguments : [];
      const spender = [v.spender, v.operator, args[0]].find((x) => typeof x === "string" && ADDR.test(x));
      if (spender) { const amt = v.amount ?? v.value ?? args[1]; return { fn: fn.replace(/\(.*$/, ""), spender, chain, unlimited: amt === true || /^(max|unlimited|infinite)$/i.test(String(amt)) || (/^\d+$/.test(String(amt)) && BigInt(String(amt)) >= MAX_UINT256 / 2n), via: "structured" }; }
    }
    if (typeof v.primaryType === "string" && PERMIT_TYPES.test(v.primaryType) && isObj(v.message)) {
      const spender = [v.message.spender, v.message?.details?.spender].find((x) => typeof x === "string" && ADDR.test(x));
      if (spender) return { fn: `sign:${v.primaryType}`, spender, chain: CHAINS[String(v.domain?.chainId ?? "").toLowerCase()] || chain, unlimited: false, via: "typed-data" };
    }
  }
  if (EXEC_TOOLS.test(name) || opts.toolKind === "code_mode_exec") {
    const cmd = commandOf(params);
    const m = /\bcast\s+send\b[^\n]*?["']?(approve|increaseAllowance|setApprovalForAll)\s*\([^)]*\)["']?\s+(0x[0-9a-fA-F]{40})/i.exec(cmd);
    if (m) { const ch = /--chain(?:-id)?\s+(\S+)/.exec(cmd)?.[1]; return { fn: m[1], spender: m[2], chain: (ch && CHAINS[ch.toLowerCase()]) || chain, unlimited: /max|uint256\.max|115792089237316195423570985008687907853269984665640564039457584007913129639935/i.test(cmd), via: "exec:cast" }; }
  }
  return null;
}
