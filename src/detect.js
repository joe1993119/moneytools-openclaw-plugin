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
  const aw = word(data, sel.amountArg); if (!aw) return null; const amount = BigInt("0x" + aw); // truncated calldata is undecodable
  // approve(addr, uint256) is shared by ERC-20 (amount) and ERC-721 (tokenId): only a zero-address spender is a certain revoke.
  // A non-zero spender with 0 is ambiguous (ERC-20 revoke or ERC-721 token #0) and is still screened.
  if (BigInt(spender) === 0n) return null;
  const unlimited = sel.fn === "permit2.approve" ? amount >= (1n << 160n) - 1n : amount >= MAX_UINT256 / 2n;
  const out = { fn: sel.fn, spender, amount: amount.toString(), unlimited };
  if (sel.fn === "approve" && amount === 0n) out.ambiguousZero = true;
  return out;
}
function chainOf(params, fallback) {
  for (const [k, v] of walk(params)) if (/^(chain|chainid|chain_id|network|chainname)$/i.test(k) && (typeof v === "string" || typeof v === "number")) { const c = CHAINS[String(v).toLowerCase()]; if (c) return c; }
  return fallback;
}

const PERMIT2_ONE = /^permit2[._]?approve$/i;
const MAX_OPS = 20, MAX_DEPTH = 12, MAX_ITEMS = 200, MAX_JSON = 200000;
const SIGN_TYPED = /^(eth_signTypedData(_v[34])?|wallet_signTypedData|signTypedData)$/i;
const typedChain = (id) => { if (id === undefined || id === null) return null; const s = String(id).toLowerCase(); const dec = /^0x[0-9a-f]+$/.test(s) ? BigInt(s).toString() : s; return CHAINS[dec] || null; };
/** JSON-RPC / signer adapter: a typed-data signing request must carry a typed-data object (or JSON string) we can read. */
function signingAdapter(v, problems) {
  const m = v.method ?? v.rpcMethod; if (typeof m !== "string" || !SIGN_TYPED.test(m)) return;
  const ps = Array.isArray(v.params) ? v.params : isObj(v.params) ? [v.params] : [];
  const ok = ps.some((p) => isObj(p) ? typeof p.primaryType === "string" : typeof p === "string" && (() => { try { return typeof JSON.parse(p)?.primaryType === "string"; } catch { return false; } })());
  if (!ok) problems.push(`${m} request without readable typed data`);
}
const fnName = (fn) => String(fn).replace(/\(.*$/, "").trim();
const isAddr = (x) => typeof x === "string" && ADDR.test(x);
const isUnlimited = (amt, bits = 256) => amt === true || /^(max|unlimited|infinite)$/i.test(String(amt)) || (/^\d+$/.test(String(amt)) && BigInt(String(amt)) >= (bits === 160 ? (1n << 160n) - 1n : MAX_UINT256 / 2n));
const chainFrom = (v) => { if (!isObj(v)) return null; for (const k of Object.keys(v)) if (/^(chain|chainid|chain_id|network|chainname)$/i.test(k) && (typeof v[k] === "string" || typeof v[k] === "number")) { const c = CHAINS[String(v[k]).toLowerCase()]; if (c) return c; } return null; };

/** Approval selectors embedded in batch calldata (multicall, multiSend, execute ...): word-aligned ones are decoded, anything else is reported as undecodable. */
function embeddedApprovals(hex, ops, problems, chain) {
  const body = hex.slice(10).toLowerCase();
  for (const sel of Object.keys(SELECTORS)) {
    const s = sel.slice(2); let at = body.indexOf(s);
    while (at !== -1) {
      const d = at % 64 === 0 ? decodeCalldata("0x" + body.slice(at)) : null;
      if (d && isAddr(d.spender)) ops.push({ ...d, chain, via: "calldata:batch" });
      else if (at % 64 === 0 && isRevoke("0x" + body.slice(at), SELECTORS[sel])) { /* certain revoke (false / zero-address spender): nothing to screen */ }
      else problems.push(`batched calldata contains a ${SELECTORS[sel].fn} call that could not be decoded`);
      at = body.indexOf(s, at + 8);
    }
  }
}

/** Structured call ({ functionName, args } and similar), decoded by its real ABI. */
function structuredApproval(v, chain, problems) {
  const raw = v.functionName ?? v.function ?? v.method ?? v.action;
  if (typeof raw !== "string" || !APPROVE_FN.test(fnName(raw))) return null;
  const name = fnName(raw); const sig = /\(([^)]*)\)/.exec(String(raw))?.[1]?.replace(/\s+/g, "") ?? null;
  const args = Array.isArray(v.args) ? v.args : Array.isArray(v.arguments) ? v.arguments : [];
  const lname = name.toLowerCase();
  let fn = name, spender, amount, unlimited, expiration, ambiguousZero = false;
  const permit2 = PERMIT2_ONE.test(name) || (lname === "approve" && (sig === "address,address,uint160,uint48" || args.length === 4));
  if (permit2) { fn = "permit2.approve"; spender = args[1] ?? v.spender; amount = args[2] ?? v.amount; expiration = args[3] ?? v.expiration; unlimited = isUnlimited(amount, 160); }
  else if (lname === "approve" || lname === "increaseallowance") {
    if (sig && sig !== "address,uint256") { problems.push(`unsupported ${name}(${sig}) signature`); return null; }
    spender = args.length ? args[0] : v.spender; amount = args.length ? args[1] : (v.amount ?? v.value); unlimited = isUnlimited(amount);
    if (isAddr(spender) && BigInt(spender) === 0n) return null; // zero-address spender: certain revoke
    if (lname === "approve" && /^0+$/.test(String(amount))) ambiguousZero = true; // ERC-20 revoke or ERC-721 token #0: still screened
  } else if (lname === "setapprovalforall") {
    spender = args.length ? args[0] : v.operator; const on = args.length ? args[1] : v.approved;
    if (on === false || on === "false" || on === 0 || on === "0") return null; unlimited = true;
  } else if (lname === "permit") { // EIP-2612 permit(owner, spender, value, deadline, v, r, s)
    spender = args.length ? args[1] : v.spender; amount = args.length ? args[2] : v.value; unlimited = isUnlimited(amount);
  } else { problems.push(`unsupported approval call ${name}`); return null; }
  // Explicit fields must agree with the arguments that will execute.
  for (const k of ["spender", "operator"]) if (isAddr(v[k]) && isAddr(spender) && v[k].toLowerCase() !== spender.toLowerCase()) { problems.push(`${name}: ${k} field ${v[k]} disagrees with the call arguments (${spender})`); return null; }
  if (!isAddr(spender)) { problems.push(`${name} call without a decodable spender`); return null; }
  const op = { fn, spender, chain: chainFrom(v) || chain, unlimited: !!unlimited, via: "structured" };
  if (amount !== undefined) op.amount = String(amount); if (expiration !== undefined) op.expiration = String(expiration); if (ambiguousZero) op.ambiguousZero = true;
  return op;
}

function typedDataApprovals(v, chain, problems) {
  if (typeof v.primaryType !== "string" || !PERMIT_TYPES.test(v.primaryType)) return [];
  const ch = typedChain(v.domain?.chainId) || chain;
  const m = v.message; if (!isObj(m)) { problems.push(`${v.primaryType} signature without a message`); return []; }
  const spender = m.spender ?? m.details?.spender;
  if (!isAddr(spender)) { problems.push(`${v.primaryType} signature without a decodable spender`); return []; }
  return [{ fn: `sign:${v.primaryType}`, spender, chain: ch, unlimited: false, via: "typed-data" }];
}

/** Every token approval this tool call would grant or sign (txs, nested/batched txs, Permit signatures, cast send),
 *  plus problems: approval-like content that could not be decoded or whose representations disagree. -> { approvals, problems } */
export function detectApprovals(toolName, params, opts = {}) {
  const name = String(toolName || ""); const approvals = [], problems = [];
  if (/^moneytools_/i.test(name)) return { approvals, problems };
  const ops = [];
  const visit = (v, chain, depth) => {
    if (depth > MAX_DEPTH) { if (v && typeof v === "object") problems.push("transaction data nested too deeply to screen"); return; }
    if (typeof v === "string") {
      const t = v.trim();
      if (t[0] === "{" || t[0] === "[") { // JSON-serialized payloads (eth_signTypedData_v4 data, stringified txs) are parsed and screened the same way
        const looksSigning = /primaryType|permit|spender|"data"\s*:\s*"0x|approve/i.test(t);
        if (t.length > MAX_JSON) { if (looksSigning) problems.push("serialized signing/transaction payload too large to screen"); return; }
        let parsed; try { parsed = JSON.parse(t); } catch { if (looksSigning) problems.push("serialized signing/transaction payload could not be parsed"); return; }
        visit(parsed, chain, depth + 1); return;
      }
      if (!/^0x[0-9a-fA-F]{8}/.test(v) || v.length === 42 || v.length === 66) return; // addresses and hashes are not calldata
      const sel = SELECTORS[v.slice(0, 10).toLowerCase()];
      if (sel) { const d = decodeCalldata(v); if (d && isAddr(d.spender)) ops.push({ ...d, chain, via: "calldata" }); else if (!d && !isRevoke(v, sel)) problems.push(`${sel.fn} calldata could not be decoded`); }
      else if (v.length > 10 + 128) embeddedApprovals(v, ops, problems, chain);
      return;
    }
    if (Array.isArray(v)) { if (v.length > MAX_ITEMS) problems.push("transaction batch too large to screen"); for (const x of v.slice(0, MAX_ITEMS)) visit(x, chain, depth + 1); return; }
    if (!isObj(v)) return;
    const ch = chainFrom(v) || chain; const keys = Object.keys(v);
    if (keys.length > MAX_ITEMS) problems.push("transaction object too large to screen");
    const st = structuredApproval(v, ch, problems); if (st) ops.push(st);
    signingAdapter(v, problems);
    ops.push(...typedDataApprovals(v, ch, problems));
    // calldata in the same object must agree with the structured call
    if (st && typeof v.data === "string") { const d = decodeCalldata(v.data); if (d && d.spender.toLowerCase() !== st.spender.toLowerCase()) problems.push(`structured ${st.fn} spender ${st.spender} disagrees with calldata spender ${d.spender}`); }
    for (const k of keys.slice(0, MAX_ITEMS)) visit(v[k], ch, depth + 1);
  };
  visit(params, chainOf(params, opts.defaultChain || "base"), 0);
  if (EXEC_TOOLS.test(name) || opts.toolKind === "code_mode_exec") {
    const cmd = commandOf(params); const chain = chainOf(params, opts.defaultChain || "base");
    const re = /\bcast\s+send\b[^\n]*?["']?(approve|increaseAllowance|setApprovalForAll)\s*\([^)]*\)["']?\s+(0x[0-9a-fA-F]{40})/gi; let m, found = 0;
    while ((m = re.exec(cmd))) { found++; const ch = /--chain(?:-id)?\s+(\S+)/.exec(cmd.slice(m.index))?.[1]; ops.push({ fn: m[1], spender: m[2], chain: (ch && CHAINS[ch.toLowerCase()]) || chain, unlimited: /max|uint256\.max|115792089237316195423570985008687907853269984665640564039457584007913129639935/i.test(cmd), via: "exec:cast" }); }
    const mentions = (cmd.match(/\b(approve|increaseAllowance|setApprovalForAll|permit)\s*\(/gi) || []).length;
    if (/\b(cast\s+send|cast\s+calldata|seth\s+send)\b/i.test(cmd) && mentions > found) problems.push("command contains an approval call that could not be parsed");
  }
  const seen = new Set();
  for (const o of ops) { const k = `${o.chain}:${o.spender.toLowerCase()}:${o.fn}`; if (!seen.has(k)) { seen.add(k); approvals.push(o); } }
  if (approvals.length > MAX_OPS) { problems.push(`${approvals.length} approvals in one call; only the first ${MAX_OPS} are screened`); approvals.length = MAX_OPS; }
  return { approvals, problems: [...new Set(problems)] };
}
/** Certain revokes only: setApprovalForAll(op, false), or any approval to the zero address. Same rule as decodeCalldata. */
function isRevoke(hex, sel) {
  const sw = word(hex, sel.spenderArg); if (sw === null) return false;
  if (BigInt("0x" + sw) === 0n) return word(hex, sel.amountArg ?? sel.boolArg) !== null;
  if (sel.boolArg !== undefined) { const b = word(hex, sel.boolArg); return b !== null && BigInt("0x" + b) === 0n; }
  return false;
}

/** First approval only (kept for compatibility; the guard uses detectApprovals). */
export function detectApproval(toolName, params, opts = {}) { return detectApprovals(toolName, params, opts).approvals[0] || null; }
