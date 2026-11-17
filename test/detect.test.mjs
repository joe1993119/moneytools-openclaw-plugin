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
