import test from "node:test"; import assert from "node:assert/strict";
import { detectX402Payment, detectApproval } from "../src/detect.js";
const SP = "0x1111111254eeb25477b68fb85ed929f73a960582";
const pad = (h) => h.replace(/^0x/, "").padStart(64, "0");
const approveData = (spender, amt) => "0x095ea7b3" + pad(spender) + pad(amt.toString(16));

test("x402: agentcash / x402 tool names with a URL are payments; plain web fetch is not", () => {
  assert.deepEqual(detectX402Payment("agentcash__fetch", { url: "https://seller.example/api" }), { url: "https://seller.example/api", method: "GET", via: "tool-name" });
  assert.equal(detectX402Payment("x402_pay", { endpoint: "https://s.example/x", method: "post" }).method, "POST");
  assert.equal(detectX402Payment("web_fetch", { url: "https://news.example/" }), null);
  assert.equal(detectX402Payment("web_fetch", { url: "https://s.example/p", headers: { "PAYMENT-SIGNATURE": "abc" } }).via, "payment-header");
});
test("x402: exec with agentcash fetch or a payment header is a payment", () => {
  assert.equal(detectX402Payment("exec", { command: 'npx agentcash fetch "https://s.example/data?q=1" -m POST' }).method, "POST");
  assert.equal(detectX402Payment("exec", { command: "curl -H 'X-PAYMENT: eyJ' https://s.example/v1/x" }).url, "https://s.example/v1/x");
  assert.equal(detectX402Payment("exec", { command: "ls -la" }), null);
});
test("x402: own MoneyTools check URLs and moneytools_ tools are never rechecked (no loops)", () => {
  assert.equal(detectX402Payment("agentcash__fetch", { url: "https://api.moneytools.dev/v1/precheck?url=x" }), null);
  assert.equal(detectX402Payment("moneytools_pay_precheck", { url: "https://s.example/" }), null);
});
test("approve: calldata approve(spender, max) on base -> unlimited", () => {
  const a = detectApproval("send_transaction", { to: "0xA0b8...", data: approveData(SP, (1n << 256n) - 1n), chainId: 8453 });
  assert.equal(a.spender, SP); assert.equal(a.chain, "base"); assert.equal(a.unlimited, true); assert.equal(a.fn, "approve");
});
test("approve: approve(spender, 0) is ambiguous (ERC-20 revoke / ERC-721 token #0) and still screened; setApprovalForAll(false) ignored", () => {
  assert.equal(detectApproval("send_transaction", { data: approveData(SP, 0n) }).ambiguousZero, true);
  assert.equal(detectApproval("send_transaction", { data: "0xa22cb465" + pad(SP) + pad("0") }), null);
  assert.equal(detectApproval("send_transaction", { data: "0xa22cb465" + pad(SP) + pad("1"), chain: "ethereum" }).chain, "ethereum");
});
test("approve: structured, Permit2 typed data, and cast send", () => {
  assert.equal(detectApproval("wallet_call", { functionName: "approve", args: [SP, "1000"], network: "arbitrum" }).chain, "arbitrum");
  const p = detectApproval("sign_typed_data", { typedData: { primaryType: "PermitSingle", domain: { chainId: 1 }, message: { details: {}, spender: SP } } });
  assert.equal(p.spender, SP); assert.equal(p.chain, "ethereum");
  const c = detectApproval("exec", { command: `cast send 0xToken "approve(address,uint256)" ${SP} 115792089237316195423570985008687907853269984665640564039457584007913129639935 --chain base` });
  assert.equal(c.spender, SP); assert.equal(c.unlimited, true);
  assert.equal(detectApproval("send_transaction", { data: "0xa9059cbb" + pad(SP) + pad("10") }), null); // transfer, not approve
});

// --- 0.1.3: every approval is found, Permit2 decoded by its ABI, undecodable/conflicting content reported ---
import { detectApprovals } from "../src/detect.js";
const BAD = "0x000000000000000000000000000000000000dead";
const TOKEN = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const permit2Data = (token, spender, amt, exp) => "0x87517c45" + pad(token) + pad(spender) + pad(amt.toString(16)) + pad(exp.toString(16));
test("batch: every approval is returned, in both orders, nested and mixed structured/calldata", () => {
  for (const batch of [[{ data: approveData(SP, 5n) }, { data: approveData(BAD, 5n) }], [{ data: approveData(BAD, 5n) }, { data: approveData(SP, 5n) }]]) {
    const r = detectApprovals("send_calls", { calls: batch, chainId: 8453 }); assert.deepEqual(r.approvals.map((a) => a.spender).sort(), [BAD, SP].sort()); assert.deepEqual(r.problems, []);
  }
  const nested = detectApprovals("wallet_sendCalls", { request: { params: [{ chainId: "0x1", calls: [{ functionName: "approve", args: [BAD, "1"], chainId: 1 }, { inner: { transactions: [{ data: approveData(SP, 1n), chainId: "eip155:1" }] } }] }] } });
  assert.equal(nested.approvals.length, 2); assert.deepEqual(nested.problems, []); assert.ok(nested.approvals.every((a) => a.chain === "ethereum"));
});
test("Permit2 approve: spender is args[1], amount args[2], expiration args[3] (structured and calldata)", () => {
  const s = detectApprovals("wallet_call", { functionName: "approve(address,address,uint160,uint48)", args: [TOKEN, BAD, "1461501637330902918203684832716283019655932542975", "1800000000"] }).approvals[0];
  assert.equal(s.spender, BAD); assert.equal(s.fn, "permit2.approve"); assert.equal(s.unlimited, true); assert.equal(s.expiration, "1800000000");
  assert.equal(detectApprovals("wallet_call", { functionName: "approve", args: [TOKEN, BAD, "10", "1800000000"] }).approvals[0].spender, BAD);
  assert.equal(detectApprovals("send_transaction", { data: permit2Data(TOKEN, BAD, 10n, 1800000000n) }).approvals[0].spender, BAD);
});
test("batched calldata (multicall bytes[]): word-aligned inner approvals are decoded; unaligned ones are reported", () => {
  const inner = approveData(BAD, 7n).slice(2); // ABI-encoded bytes[] with one element: offset, length, offset, len, data (padded)
  const mc = "0xac9650d8" + pad("20") + pad("1") + pad("20") + pad((inner.length / 2).toString(16)) + inner + "0".repeat(56);
  assert.equal(detectApprovals("send_transaction", { data: mc }).approvals[0].spender, BAD);
  const packed = "0x8d80ff0a" + pad("20") + pad("99") + "00" + TOKEN.slice(2) + "0".repeat(64) + pad("44") + inner; // Safe multiSend: tightly packed
  const r = detectApprovals("send_transaction", { data: packed }); assert.ok(r.problems.some((p) => /batched calldata/.test(p)), JSON.stringify(r));
});
test("conflicting or undecodable approval content is reported, never silently skipped", () => {
  assert.match(detectApprovals("wallet_call", { functionName: "approve", spender: SP, args: [BAD, "1"] }).problems[0], /disagrees/);
  assert.match(detectApprovals("wallet_call", { functionName: "approve", args: [SP, "1"], data: approveData(BAD, 1n) }).problems[0], /disagrees/);
  assert.match(detectApprovals("wallet_call", { functionName: "approve", args: ["not-an-address", "1"] }).problems[0], /spender/);
  assert.match(detectApprovals("send_transaction", { data: "0x095ea7b3" + pad(SP) }).problems[0], /could not be decoded/);
  assert.match(detectApprovals("sign_typed_data", { primaryType: "PermitSingle", message: { details: {} } }).problems[0], /spender/);
  assert.equal(detectApprovals("wallet_call", { functionName: "approve", args: [SP, "0"] }).approvals[0].ambiguousZero, true, "ambiguous zero is screened");
  const deep = {}; let n = deep; for (let i = 0; i < 14; i++) { n.x = {}; n = n.x; } n.data = approveData(BAD, 1n);
  assert.ok(detectApprovals("send_transaction", deep).problems.some((p) => /nested too deeply/.test(p)));
  assert.ok(detectApprovals("exec", { command: `cast send 0xT "approve(address,uint256)" ${SP} 1 && cast send 0xT "approve(address,uint256)" $SPENDER 1` }).problems.length >= 1);
  const two = detectApprovals("exec", { command: `cast send 0xT "approve(address,uint256)" ${SP} 1; cast send 0xT "approve(address,uint256)" ${BAD} 1` });
  assert.equal(two.approvals.length, 2); assert.deepEqual(two.problems, []);
});

// --- 0.1.3 rescan: ERC-721 token #0 and JSON-serialized typed data ---
const ZERO = "0x0000000000000000000000000000000000000000";
test("revocation semantics: only a zero-address spender or setApprovalForAll(false) is a certain revoke; same rule for calldata, structured and batched", () => {
  // ERC-721 approve(spender, tokenId 0) and ERC-20 approve(spender, 0): screened, flagged ambiguous
  const c = detectApprovals("send_transaction", { data: approveData(BAD, 0n) }); assert.equal(c.approvals[0].spender, BAD); assert.equal(c.approvals[0].ambiguousZero, true); assert.deepEqual(c.problems, []);
  const st = detectApprovals("wallet_call", { functionName: "approve", args: [BAD, 0] }); assert.equal(st.approvals[0].ambiguousZero, true);
  // ERC-721 revoke approve(address(0), tokenId) and zero-address ERC-20 approval: not screened, not a problem
  for (const r of [detectApprovals("send_transaction", { data: approveData(ZERO, 5n) }), detectApprovals("wallet_call", { functionName: "approve", args: [ZERO, "5"] })]) { assert.equal(r.approvals.length, 0); assert.deepEqual(r.problems, []); }
  // batched: inner approve(BAD, 0) is screened, inner approve(0x0, 7) is a revoke
  const inner = (sp, n) => approveData(sp, n).slice(2); const mc = (x) => "0xac9650d8" + pad("20") + pad("1") + pad("20") + pad((x.length / 2).toString(16)) + x + "0".repeat(56);
  assert.equal(detectApprovals("send_transaction", { data: mc(inner(BAD, 0n)) }).approvals[0].spender, BAD);
  const rv = detectApprovals("send_transaction", { data: mc(inner(ZERO, 7n)) }); assert.equal(rv.approvals.length, 0); assert.deepEqual(rv.problems, []);
});
const permitTD = (primaryType, message, chainId = 8453) => ({ types: { EIP712Domain: [] }, primaryType, domain: { name: "X", chainId, verifyingContract: TOKEN }, message });
test("typed data: object form and JSON-string form give the same result (EIP-2612 Permit, PermitSingle, PermitBatch), incl. eth_signTypedData_v4", () => {
  const cases = [permitTD("Permit", { owner: SP, spender: BAD, value: "1", nonce: 0, deadline: 1 }), permitTD("PermitSingle", { details: { token: TOKEN, amount: "1" }, spender: BAD, sigDeadline: 1 }, "0x2105"), permitTD("PermitBatch", { details: [{ token: TOKEN }], spender: BAD, sigDeadline: 1 }, 1)];
  for (const td of cases) {
    const a = detectApprovals("sign_typed_data", { typedData: td }).approvals[0]; const b = detectApprovals("sign_typed_data", { typedData: JSON.stringify(td) }).approvals[0];
    const rpc = detectApprovals("wallet_request", { method: "eth_signTypedData_v4", params: [SP, JSON.stringify(td)] }).approvals[0];
    assert.equal(a.spender, BAD); assert.deepEqual(b, a); assert.deepEqual(rpc, a);
  }
  assert.equal(detectApprovals("sign_typed_data", { typedData: JSON.stringify(cases[1]) }).approvals[0].chain, "base");
});
test("typed data: malformed, oversized or unreadable signing payloads are reported", () => {
  assert.match(detectApprovals("sign_typed_data", { typedData: '{"primaryType":"Permit","message":{"spender":' }).problems.join(), /could not be parsed/);
  const big = JSON.stringify(permitTD("Permit", { spender: BAD, pad: "x".repeat(250000) }));
  assert.match(detectApprovals("sign_typed_data", { typedData: big }).problems.join(), /too large/);
  assert.match(detectApprovals("wallet_request", { method: "eth_signTypedData_v4", params: [SP, "not json"] }).problems.join(), /without readable typed data/);
  assert.match(detectApprovals("sign_typed_data", { typedData: JSON.stringify(permitTD("PermitSingle", { details: {} })) }).problems.join(), /spender/);
  assert.deepEqual(detectApprovals("chat", { text: "[1, 2, 3]" }), { approvals: [], problems: [] }, "unrelated JSON is ignored");
});

// --- 0.1.4 rescan: chain identifiers and raw permit calldata ---
test("chain ids: 0x1, 1, \"1\", ethereum and eip155:1 give the same screening chain; unsupported and conflicting ids are reported", () => {
  for (const id of ["0x1", 1, "1", "ethereum", "eip155:1", "EIP155:0x1"]) { const r = detectApprovals("send_transaction", { data: approveData(SP, 5n), chainId: id }); assert.equal(r.approvals[0].chain, "ethereum", String(id)); assert.deepEqual(r.problems, []); }
  assert.equal(detectApprovals("send_transaction", { tx: { data: approveData(SP, 5n) }, options: { chainId: "0x2105" } }).approvals[0].chain, "base");
  const un = detectApprovals("send_transaction", { data: approveData(SP, 5n), chainId: "0x1234567" }); assert.equal(un.approvals.length, 0); assert.match(un.problems[0], /unsupported chain/);
  const cf = detectApprovals("send_transaction", { data: approveData(SP, 5n), chainId: 1, network: "base" }); assert.equal(cf.approvals.length, 0); assert.match(cf.problems[0], /conflicting/);
  const nest = detectApprovals("wallet_sendCalls", { chainId: "0x1", calls: [{ data: approveData(SP, 5n), chainId: 8453 }] }); assert.equal(nest.approvals.length, 0); assert.match(nest.problems[0], /conflicting/);
  assert.equal(detectApprovals("sign_typed_data", { typedData: { primaryType: "Permit", domain: { chainId: "0xa4b1" }, message: { spender: SP } } }).approvals[0].chain, "arbitrum");
  assert.match(detectApprovals("sign_typed_data", { typedData: { primaryType: "Permit", domain: { chainId: 999999 }, message: { spender: SP } } }).problems[0], /unsupported chain/);
  assert.equal(detectApprovals("send_transaction", { data: approveData(SP, 5n) }).approvals[0].chain, "base", "absent -> default");
});
const w = (x) => pad(typeof x === "bigint" ? x.toString(16) : x);
const permitData = (owner, spender, value) => "0xd505accf" + w(owner) + w(spender) + w(value) + w(9999999999n) + w(27n) + "ab".repeat(32) + "cd".repeat(32);
const daiPermit = (spender, allowed) => "0x8fcbaf0c" + w(SP) + w(spender) + w(0n) + w(0n) + w(allowed ? 1n : 0n) + w(27n) + "ab".repeat(32) + "cd".repeat(32);
const p2Single = (spender) => "0x2b67b570" + w(SP) + w(TOKEN) + w((1n << 160n) - 1n) + w(1800000000n) + w(0n) + w(spender) + w(1800000000n) + w(0x100n) + w(65n) + "ab".repeat(65) + "00".repeat(31);
const p2Batch = (spender) => "0x2a2d80d1" + w(SP) + w(0x60n) + w(0x140n) + w(0x60n) + w(spender) + w(1800000000n) + w(1n) + w(TOKEN) + w(5n) + w(1800000000n) + w(0n) + w(65n) + "ab".repeat(65) + "00".repeat(31);
test("raw permit calldata: EIP-2612, DAI permit, Permit2 permit (single and batch) are decoded like their structured forms", () => {
  const e = detectApprovals("send_transaction", { data: permitData(SP, BAD, 10n) }).approvals[0]; assert.equal(e.fn, "permit"); assert.equal(e.spender, BAD); assert.equal(e.amount, "10");
  assert.equal(detectApprovals("wallet_call", { functionName: "permit", args: [SP, BAD, "10", "9999999999", 27, "0x" + "ab".repeat(32), "0x" + "cd".repeat(32)] }).approvals[0].spender, BAD);
  assert.equal(detectApprovals("send_transaction", { data: daiPermit(BAD, true) }).approvals[0].spender, BAD);
  assert.equal(detectApprovals("send_transaction", { data: daiPermit(BAD, false) }).approvals.length, 0);
  assert.equal(detectApprovals("wallet_call", { functionName: "permit", args: [SP, BAD, 0, 0, true, 27, "0x", "0x"] }).approvals[0].fn, "permit.dai");
  const s1 = detectApprovals("send_transaction", { data: p2Single(BAD) }).approvals[0]; assert.equal(s1.fn, "permit2.permit"); assert.equal(s1.spender, BAD); assert.equal(s1.unlimited, true);
  assert.equal(detectApprovals("wallet_call", { functionName: "permit", args: [SP, { details: { token: TOKEN, amount: "5" }, spender: BAD, sigDeadline: "1" }, "0x"] }).approvals[0].spender, BAD);
  const b1 = detectApprovals("send_transaction", { data: p2Batch(BAD) }).approvals[0]; assert.equal(b1.fn, "permit2.permitBatch"); assert.equal(b1.spender, BAD);
  // nested in a batch, and truncated/malformed
  assert.equal(detectApprovals("wallet_sendCalls", { calls: [{ data: approveData(SP, 1n) }, { data: permitData(SP, BAD, 1n) }] }).approvals.length, 2);
  assert.match(detectApprovals("send_transaction", { data: permitData(SP, BAD, 1n).slice(0, 10 + 64 * 2) }).problems[0], /could not be decoded/);
  assert.match(detectApprovals("send_transaction", { data: "0x2a2d80d1" + w(SP) + w(0x7fffn) }).problems[0], /could not be decoded/);
});
