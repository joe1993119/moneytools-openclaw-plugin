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
test("approve: approve(spender, 0) is a revoke and is not checked; setApprovalForAll(false) ignored", () => {
  assert.equal(detectApproval("send_transaction", { data: approveData(SP, 0n) }), null);
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
  const nested = detectApprovals("wallet_sendCalls", { request: { params: [{ chainId: "0x1", calls: [{ functionName: "approve", args: [BAD, "1"], chainId: 1 }, { inner: { transactions: [{ data: approveData(SP, 1n), chainId: 42161 }] } }] }] } });
  assert.equal(nested.approvals.length, 2); assert.equal(nested.approvals.find((a) => a.spender === SP).chain, "arbitrum"); assert.equal(nested.approvals.find((a) => a.spender === BAD).chain, "ethereum");
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
  assert.equal(detectApprovals("wallet_call", { functionName: "approve", args: [SP, "0"] }).approvals.length, 0, "revoke");
  const deep = {}; let n = deep; for (let i = 0; i < 14; i++) { n.x = {}; n = n.x; } n.data = approveData(BAD, 1n);
  assert.ok(detectApprovals("send_transaction", deep).problems.some((p) => /nested too deeply/.test(p)));
  assert.ok(detectApprovals("exec", { command: `cast send 0xT "approve(address,uint256)" ${SP} 1 && cast send 0xT "approve(address,uint256)" $SPENDER 1` }).problems.length >= 1);
  const two = detectApprovals("exec", { command: `cast send 0xT "approve(address,uint256)" ${SP} 1; cast send 0xT "approve(address,uint256)" ${BAD} 1` });
  assert.equal(two.approvals.length, 2); assert.deepEqual(two.problems, []);
});
