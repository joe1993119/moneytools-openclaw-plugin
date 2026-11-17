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
  // EIP-2612 permit(owner, spender, value, deadline, v, r, s)
  "0xd505accf": { fn: "permit", spenderArg: 1, amountArg: 2 },
  // DAI-style permit(holder, spender, nonce, expiry, allowed, v, r, s)
  "0x8fcbaf0c": { fn: "permit.dai", spenderArg: 1, boolArg: 4 },
  // Permit2 permit(owner, PermitSingle{details{token, amount, expiration, nonce}, spender, sigDeadline}, signature): static tuple inline
  "0x2b67b570": { fn: "permit2.permit", spenderArg: 5, amountArg: 2 },
  // Permit2 permit(owner, PermitBatch{details[], spender, sigDeadline}, signature): dynamic tuple, spender = 2nd word of the tuple
  "0x2a2d80d1": { fn: "permit2.permitBatch", spenderArg: (hex) => { const o = word(hex, 1); if (!o) return null; const off = BigInt("0x" + o); return off % 32n === 0n && off < 1n << 20n ? Number(off / 32n) + 1 : null; }, noAmount: true },
};
const spenderIdx = (hex, sel) => (typeof sel.spenderArg === "function" ? sel.spenderArg(hex) : sel.spenderArg);
const APPROVE_FN = /^(approve|increaseallowance|setapprovalforall|permit|permit2[._]?approve)$/i;
const PERMIT2_TYPES = /^(permitsingle|permitbatch|permittransferfrom|permitbatchtransferfrom|permitwitnesstransferfrom|permitbatchwitnesstransferfrom)$/i;
const PERMIT2_ADDRESS = "0x000000000022d473030f116ddee9f6b43ac78ba3"; // canonical Permit2 (same address on every supported chain)
const MAX_UINT256 = (1n << 256n) - 1n;
const ADDR = /^0x[0-9a-fA-F]{40}$/;

export const CHAINS = { base: "base", "8453": "base", "eip155:8453": "base", ethereum: "ethereum", mainnet: "ethereum", eth: "ethereum", "1": "ethereum", "eip155:1": "ethereum",
  arbitrum: "arbitrum", "arbitrum-one": "arbitrum", "42161": "arbitrum", "eip155:42161": "arbitrum", optimism: "optimism", op: "optimism", "10": "optimism", "eip155:10": "optimism",
  polygon: "polygon", matic: "polygon", "137": "polygon", "eip155:137": "polygon", bsc: "bsc", bnb: "bsc", "56": "bsc", "eip155:56": "bsc", avalanche: "avalanche", avax: "avalanche", "43114": "avalanche", "eip155:43114": "avalanche",
  "base-mainnet": "base", "ethereum-mainnet": "ethereum", "eth-mainnet": "ethereum", homestead: "ethereum", "arbitrum-mainnet": "arbitrum", arb1: "arbitrum", "optimism-mainnet": "optimism", "op-mainnet": "optimism",
  "polygon-mainnet": "polygon", "matic-mainnet": "polygon", "bsc-mainnet": "bsc", binance: "bsc", "avalanche-c": "avalanche", "avax-c": "avalanche" };

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
function* walk(v, depth = 0, key = "") { if (depth > 6) return; yield [key, v]; if (Array.isArray(v)) { for (const x of v.slice(0, 50)) yield* walk(x, depth + 1, key); } else if (isObj(v)) { for (const [k, x] of Object.entries(v).slice(0, 100)) yield* walk(x, depth + 1, k); } }
// Returned URLs carry only scheme, host, port and path: user info, query string and fragment are dropped so they never reach logs or the check API.
export const stripUrl = (s) => { if (typeof s !== "string") return null; try { const u = new URL(s.trim()); if (!/^https?:$/.test(u.protocol)) return null; u.username = ""; u.password = ""; u.search = ""; u.hash = ""; return u.toString(); } catch { return null; } };
const httpUrl = stripUrl;

export function isOwnCheckUrl(url) { try { return /(^|\.)moneytools\.dev$/i.test(new URL(url).hostname); } catch { return false; } }

/** Raw URL string as given (only used to tell whether it had a query string; the stripped form is what is returned and sent). */
function findUrl(params) {
  for (const k of URL_KEYS) { if (httpUrl(params?.[k])) return params[k]; }
  for (const k of ["request", "input", "args", "arguments"]) if (isObj(params?.[k])) { const u = findUrl(params[k]); if (u) return u; }
  return null;
}
const hasQuery = (s) => { try { return new URL(String(s).trim()).search.length > 1; } catch { return false; } };
// The precheck only sees scheme/host/path; a payment URL with a query string is flagged so the guard can say the query was not screened.
const pay = (raw, method, via) => ({ url: stripUrl(raw), method, via, hasQuery: hasQuery(raw) });
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
    if (m && !isOwnCheckUrl(m[1]) && stripUrl(m[1])) return pay(m[1], /(?:-m|--method)\s+(POST|PUT|PATCH|DELETE)/i.exec(cmd)?.[1]?.toUpperCase() || "GET", "exec:agentcash");
    if (/(payment-signature|x-payment)\s*:/i.test(cmd)) { const u = /(https?:\/\/[^\s"']+)/.exec(cmd)?.[1]; if (u && !isOwnCheckUrl(u) && stripUrl(u)) return pay(u, /-X\s+(POST|PUT|PATCH|DELETE)/i.exec(cmd)?.[1]?.toUpperCase() || "GET", "exec:payment-header"); }
    return null;
  }
  const raw = findUrl(params); if (!raw || isOwnCheckUrl(raw)) return null;
  if (hasPaymentHeader(params)) return pay(raw, method, "payment-header");
  if (pattern.test(name)) return pay(raw, method, "tool-name");
  return null;
}

function word(hex, i) { const w = hex.slice(10 + 64 * i, 10 + 64 * (i + 1)); return w.length === 64 ? w : null; }
function decodeCalldata(data) {
  if (typeof data !== "string" || !/^0x[0-9a-fA-F]{8}/.test(data)) return null;
  const sel = SELECTORS[data.slice(0, 10).toLowerCase()]; if (!sel) return null;
  const si = spenderIdx(data, sel); const sw = si === null ? null : word(data, si); if (!sw || !/^0{24}/.test(sw)) return null;
  const spender = "0x" + sw.slice(24);
  if (BigInt(spender) === 0n) return null; // approval to the zero address grants nothing
  if (sel.boolArg !== undefined) { const b = word(data, sel.boolArg); if (!b || BigInt("0x" + b) === 0n) return null; return { fn: sel.fn, spender, unlimited: true }; }
  if (sel.noAmount) return { fn: sel.fn, spender, unlimited: false };
  const aw = word(data, sel.amountArg); if (!aw) return null; const amount = BigInt("0x" + aw); // truncated calldata is undecodable
  // approve(addr, uint256) is shared by ERC-20 (amount) and ERC-721 (tokenId): only a zero-address spender is a certain revoke.
  // A non-zero spender with 0 is ambiguous (ERC-20 revoke or ERC-721 token #0) and is still screened.
  const unlimited = sel.fn.startsWith("permit2.") ? amount >= (1n << 160n) - 1n : amount >= MAX_UINT256 / 2n;
  const out = { fn: sel.fn, spender, amount: amount.toString(), unlimited };
  if (sel.fn === "approve" && amount === 0n) out.ambiguousZero = true;
  return out;
}
const CHAIN_KEY = /^(chain|chainid|chain_id|network|chainname)$/i;
/** One normalizer for every chain identifier: names, decimal / hex ids, numbers, CAIP-2 (eip155:N). -> { chain } | { unsupported } | null (absent) */
export function normalizeChain(raw) {
  if (raw === undefined || raw === null || raw === "" || (typeof raw !== "string" && typeof raw !== "number" && typeof raw !== "bigint")) return null;
  let s = String(raw).trim().toLowerCase(); const caip = /^eip155:(.+)$/.exec(s); if (caip) s = caip[1];
  if (/^0x[0-9a-f]+$/.test(s) || /^\d+$/.test(s)) s = BigInt(s).toString();
  const c = CHAINS[s]; return c ? { chain: c } : { unsupported: String(raw) };
}
/** Chain declared on one object. Several identifiers on the same object must agree. -> chain name | "?unsupported:x" | "?conflict:a/b" | null */
function chainFrom(v) {
  if (!isObj(v)) return null; const found = [];
  for (const k of Object.keys(v)) if (CHAIN_KEY.test(k)) { const n = normalizeChain(v[k]); if (n) found.push(n.chain || `?unsupported:${n.unsupported}`); }
  const uniq = [...new Set(found)]; if (!uniq.length) return null; if (uniq.length === 1) return uniq[0];
  return `?conflict:${uniq.join("/")}`;
}
/** Chain for the whole call when the approval's own objects do not declare one: the only chain declared anywhere, else the default when none is declared. */
function chainOf(params, fallback) {
  const found = new Set();
  for (const [k, v] of walk(params)) if (CHAIN_KEY.test(k)) { const n = normalizeChain(v); if (n) found.add(n.chain || `?unsupported:${n.unsupported}`); }
  if (!found.size) return fallback; if (found.size === 1) return [...found][0];
  return `?conflict:${[...found].join("/")}`;
}

const PERMIT2_ONE = /^permit2[._]?approve$/i;
const MAX_OPS = 20, MAX_DEPTH = 12, MAX_ITEMS = 200, MAX_JSON = 200000;
const SIGN_TYPED = /^(eth_signTypedData(_v[34])?|wallet_signTypedData|signTypedData)$/i;
const typedChain = (id) => { const n = normalizeChain(id); return n ? n.chain || `?unsupported:${n.unsupported}` : null; };
/** JSON-RPC / signer adapter: a typed-data signing request must carry a typed-data object (or JSON string) we can read. */
function signingAdapter(v, problems) {
  const m = v.method ?? v.rpcMethod; if (typeof m !== "string" || !SIGN_TYPED.test(m)) return;
  const ps = Array.isArray(v.params) ? v.params : isObj(v.params) ? [v.params] : [];
  const readable = (t) => isObj(t) && typeof t.primaryType === "string" && isObj(t.domain) && isObj(t.message) && isObj(t.types);
  const ok = ps.some((p) => readable(p) || (typeof p === "string" && p.length <= MAX_JSON && (() => { try { return readable(JSON.parse(p)); } catch { return false; } })()));
  if (!ok) problems.push(`${m} request without readable typed data`);
}
const fnName = (fn) => String(fn).replace(/\(.*$/, "").trim();
const isAddr = (x) => typeof x === "string" && ADDR.test(x);
const isUnlimited = (amt, bits = 256) => amt === true || /^(max|unlimited|infinite)$/i.test(String(amt)) || (/^\d+$/.test(String(amt)) && BigInt(String(amt)) >= (bits === 160 ? (1n << 160n) - 1n : MAX_UINT256 / 2n));

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
  } else if (lname === "permit" && isObj(args[1])) { // Permit2 permit(owner, PermitSingle | PermitBatch, signature)
    fn = Array.isArray(args[1].details) ? "permit2.permitBatch" : "permit2.permit"; spender = args[1].spender; amount = Array.isArray(args[1].details) ? undefined : args[1].details?.amount; unlimited = isUnlimited(amount, 160);
  } else if (lname === "permit" && (args.length === 8 || sig === "address,address,uint256,uint256,bool,uint8,bytes32,bytes32")) { // DAI permit(holder, spender, nonce, expiry, allowed, v, r, s)
    fn = "permit.dai"; spender = args[1]; const on = args[4]; if (on === false || on === "false" || on === 0 || on === "0") return null; unlimited = true;
  } else if (lname === "permit") { // EIP-2612 permit(owner, spender, value, deadline, v, r, s)
    spender = args.length ? args[1] : v.spender; amount = args.length ? args[2] : v.value; unlimited = isUnlimited(amount);
  } else { problems.push(`unsupported approval call ${name}`); return null; }
  // Explicit fields must agree with the arguments that will execute.
  for (const k of ["spender", "operator"]) if (isAddr(v[k]) && isAddr(spender) && v[k].toLowerCase() !== spender.toLowerCase()) { problems.push(`${name}: ${k} field ${v[k]} disagrees with the call arguments (${spender})`); return null; }
  if (!isAddr(spender)) { problems.push(`${name} call without a decodable spender`); return null; }
  if (BigInt(spender) === 0n) return null; // approval to the zero address grants nothing
  const op = { fn, spender, chain, unlimited: !!unlimited, via: "structured" };
  if (amount !== undefined) op.amount = String(amount); if (expiration !== undefined) op.expiration = String(expiration); if (ambiguousZero) op.ambiguousZero = true;
  return op;
}

const DAI_PERMIT_FIELDS = [["holder", "address"], ["spender", "address"], ["nonce", "uint256"], ["expiry", "uint256"], ["allowed", "bool"]];
function isDaiPermitType(pt, types) {
  const f = /^permit$/i.test(pt) && isObj(types) ? types[pt] : null;
  return Array.isArray(f) && f.length === DAI_PERMIT_FIELDS.length && f.every((x, i) => isObj(x) && x.name === DAI_PERMIT_FIELDS[i][0] && x.type === DAI_PERMIT_FIELDS[i][1]);
}
/** EIP-712 permits: EIP-2612 / DAI Permit and every Permit2 type (allowance, transfer, witness transfer; single and batch).
 *  The domain (verifying contract, chain) and type definitions are checked; unknown permit-like types are reported, never ignored. */
function typedDataApprovals(v, chain, problems) {
  if (typeof v.primaryType !== "string") return [];
  const pt = v.primaryType; const d = isObj(v.domain) ? v.domain : null; const m = isObj(v.message) ? v.message : null;
  const vc = typeof d?.verifyingContract === "string" ? d.verifyingContract.toLowerCase() : null;
  const isP2 = PERMIT2_TYPES.test(pt) || vc === PERMIT2_ADDRESS || /^permit2$/i.test(String(d?.name ?? ""));
  const known = PERMIT2_TYPES.test(pt) || /^permit$/i.test(pt);
  if (!known) {
    if (isP2) { problems.push(`unsupported Permit2 typed data ${pt}`); return []; }
    if (/permit|approv|allowance|delegat/i.test(pt)) { problems.push(`unsupported authorization typed data ${pt}`); return []; }
    if (m && isAddr(m.spender) && BigInt(m.spender) !== 0n) return [{ fn: `sign:${pt}`, spender: m.spender, chain: typedChain(d?.chainId) || chain, unlimited: false, via: "typed-data", ...(vc && isAddr(vc) ? { token: d.verifyingContract } : {}) }];
    return [];
  }
  if (!m) { problems.push(`${pt} signature without a message`); return []; }
  if (!d) { problems.push(`${pt} signature without a domain`); return []; }
  if (!isObj(v.types) || !Array.isArray(v.types[pt])) problems.push(`${pt} signature whose types do not define ${pt}`);
  if (isP2 && vc !== PERMIT2_ADDRESS) problems.push(`${pt} signature for verifying contract ${d.verifyingContract ?? "(none)"}, not the canonical Permit2`);
  if (!isP2 && !(vc && isAddr(vc))) problems.push(`${pt} signature without a token verifying contract`);
  const spender = m.spender ?? m.details?.spender;
  if (!isAddr(spender)) { problems.push(`${pt} signature without a decodable spender`); return []; }
  if (BigInt(spender) === 0n) return [];
  // DAI permit revoke only when the signed type is exactly DAI's Permit(holder, spender, nonce, expiry, bool allowed); an unsigned `allowed` property is ignored.
  if (isDaiPermitType(pt, v.types) && (m.allowed === false || m.allowed === "false" || m.allowed === 0 || m.allowed === "0")) return [];
  const permitted = m.permitted ?? m.details; const first = Array.isArray(permitted) ? permitted[0] : permitted;
  const token = isP2 ? (isAddr(first?.token) ? first.token : null) : d.verifyingContract;
  const amount = Array.isArray(permitted) ? undefined : (first?.amount ?? m.value);
  const op = { fn: `sign:${pt}`, spender, chain: typedChain(d.chainId) || chain, unlimited: amount !== undefined && isUnlimited(amount, isP2 ? 160 : 256), via: "typed-data" };
  if (token) op.token = token; if (Array.isArray(permitted)) op.tokens = permitted.length; if (amount !== undefined && amount !== null) op.amount = String(amount);
  return [op];
}

/** Every token approval this tool call would grant or sign (txs, nested/batched txs, Permit signatures, cast send),
 *  plus problems: approval-like content that could not be decoded or whose representations disagree. -> { approvals, problems } */
export function detectApprovals(toolName, params, opts = {}) {
  const name = String(toolName || ""); const approvals = [], problems = [];
  if (/^moneytools_/i.test(name)) return { approvals, problems };
  const ops = [];
  const visit = (v, chain, depth, explicit = false, to = null) => {
    if (depth > MAX_DEPTH) { if (v && typeof v === "object") problems.push("transaction data nested too deeply to screen"); return; }
    if (typeof v === "string") {
      const t = v.trim();
      if (t[0] === "{" || t[0] === "[") { // JSON-serialized payloads (eth_signTypedData_v4 data, stringified txs) are parsed and screened the same way
        const looksSigning = /primaryType|permit|spender|"data"\s*:\s*"0x|approve/i.test(t);
        if (t.length > MAX_JSON) { if (looksSigning) problems.push("serialized signing/transaction payload too large to screen"); return; }
        let parsed; try { parsed = JSON.parse(t); } catch { if (looksSigning) problems.push("serialized signing/transaction payload could not be parsed"); return; }
        visit(parsed, chain, depth + 1, explicit, to); return;
      }
      if (!/^0x[0-9a-fA-F]{8}/.test(v) || v.length === 42 || v.length === 66) return; // addresses and hashes are not calldata
      const sel = SELECTORS[v.slice(0, 10).toLowerCase()];
      if (sel) { const d = decodeCalldata(v); if (d && isAddr(d.spender)) ops.push({ ...d, chain, via: "calldata", ...(to ? { token: to } : {}) }); else if (!d && !isRevoke(v, sel)) problems.push(`${sel.fn} calldata could not be decoded`); }
      else if (v.length > 10 + 128) embeddedApprovals(v, ops, problems, chain);
      return;
    }
    if (Array.isArray(v)) { if (v.length > MAX_ITEMS) problems.push("transaction batch too large to screen"); for (const x of v.slice(0, MAX_ITEMS)) visit(x, chain, depth + 1, explicit, null); return; }
    if (!isObj(v)) return;
    const own = chainFrom(v);
    // A nested object may not silently switch away from a chain its parent declared explicitly.
    const ch = !own ? chain : explicit && chain !== own && !own.startsWith("?") && !chain.startsWith("?") ? `?conflict:${chain}/${own}` : own;
    const isExplicit = explicit || !!own; const keys = Object.keys(v);
    if (keys.length > MAX_ITEMS) problems.push("transaction object too large to screen");
    const txTo = isAddr(v.to) ? v.to : isAddr(v.address) ? v.address : isAddr(v.contract) ? v.contract : null;
    const st = structuredApproval(v, ch, problems); if (st) { if (txTo) st.token = txTo; ops.push(st); }
    signingAdapter(v, problems);
    ops.push(...typedDataApprovals(v, ch, problems));
    // calldata in the same object must agree with the structured call
    if (st && typeof v.data === "string") { const d = decodeCalldata(v.data); if (d && d.spender.toLowerCase() !== st.spender.toLowerCase()) problems.push(`structured ${st.fn} spender ${st.spender} disagrees with calldata spender ${d.spender}`); }
    for (const k of keys.slice(0, MAX_ITEMS)) visit(v[k], ch, depth + 1, isExplicit, txTo);
  };
  visit(params, chainOf(params, opts.defaultChain || "base"), 0, false);
  if (EXEC_TOOLS.test(name) || opts.toolKind === "code_mode_exec") {
    const cmd = commandOf(params); const chain = chainOf(params, opts.defaultChain || "base");
    const re = /\bcast\s+send\b[^\n]*?["']?(approve|increaseAllowance|setApprovalForAll)\s*\([^)]*\)["']?\s+(0x[0-9a-fA-F]{40})/gi; let m, found = 0;
    while ((m = re.exec(cmd))) { found++; const ch = normalizeChain(/--chain(?:-id)?\s+(\S+)/.exec(cmd.slice(m.index))?.[1]); ops.push({ fn: m[1], spender: m[2], chain: ch ? ch.chain || `?unsupported:${ch.unsupported}` : chain, unlimited: /max|uint256\.max|115792089237316195423570985008687907853269984665640564039457584007913129639935/i.test(cmd), via: "exec:cast" }); }
    const mentions = (cmd.match(/\b(approve|increaseAllowance|setApprovalForAll|permit)\s*\(/gi) || []).length;
    if (/\b(cast\s+send|cast\s+calldata|seth\s+send)\b/i.test(cmd) && mentions > found) problems.push("command contains an approval call that could not be parsed");
  }
  const seen = new Set();
  for (const o of ops) {
    // Never screen on a guessed network: unsupported or conflicting chain identifiers go to onCheckError.
    if (o.chain.startsWith("?")) { const [kind, val] = o.chain.slice(1).split(/:(.*)/); problems.push(`${o.fn} to ${o.spender}: ${kind === "conflict" ? "conflicting chain identifiers" : "unsupported chain"} ${val}`); continue; } 
    // Only exact duplicates are merged; every operation with a different fn, token, amount or revoke status is kept and judged on its own.
    const k = JSON.stringify([o.chain, o.spender.toLowerCase(), o.fn, (o.token || "").toLowerCase(), o.amount ?? null, !!o.unlimited, !!o.ambiguousZero, o.expiration ?? null]); if (!seen.has(k)) { seen.add(k); approvals.push(o); } }
  if (approvals.length > MAX_OPS) { problems.push(`${approvals.length} approvals in one call; only the first ${MAX_OPS} are screened`); approvals.length = MAX_OPS; }
  return { approvals, problems: [...new Set(problems)] };
}
/** Certain revokes only: setApprovalForAll(op, false), or any approval to the zero address. Same rule as decodeCalldata. */
function isRevoke(hex, sel) {
  const si = spenderIdx(hex, sel); const sw = si === null ? null : word(hex, si); if (sw === null) return false;
  if (BigInt("0x" + sw) === 0n) return sel.noAmount || word(hex, sel.amountArg ?? sel.boolArg) !== null;
  if (sel.boolArg !== undefined) { const b = word(hex, sel.boolArg); return b !== null && BigInt("0x" + b) === 0n; }
  return false;
}

/** First approval only (kept for compatibility; the guard uses detectApprovals). */
export function detectApproval(toolName, params, opts = {}) { return detectApprovals(toolName, params, opts).approvals[0] || null; }
