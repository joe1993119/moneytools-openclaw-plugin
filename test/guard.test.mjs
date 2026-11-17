import test from "node:test"; import assert from "node:assert/strict";
import { createGuard, registerGuard, decideRisk, decidePrecheck, readConfig } from "../src/guard.js";
import { verifyQuote, resolvePayer, MONEYTOOLS_PAY_TO } from "../src/checks.js";

const SP = "0x1111111254eeb25477b68fb85ed929f73a960582";
const approveTx = { data: "0x095ea7b3" + SP.slice(2).padStart(64, "0") + "f".repeat(64), chainId: 8453 };
const quote = (amount, payTo = MONEYTOOLS_PAY_TO, network = "eip155:8453") => ({ x402Version: 2, accepts: [{ scheme: "exact", network, amount: String(amount), asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo, maxTimeoutSeconds: 300 }] });
const res402 = (q) => new Response(JSON.stringify(q), { status: 402, headers: { "content-type": "application/json", "payment-required": Buffer.from(JSON.stringify(q)).toString("base64") } });
const res200 = (o) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
const KEYENV = { X402_PRIVATE_KEY: "0x" + "11".repeat(32) };
function fakeX402(paidBody, status = 200) { const calls = []; return { calls, mods: { accounts: { privateKeyToAccount: (k) => ({ address: "0xabc", k }) }, evm: { registerExactEvmScheme: () => {} },
  fetch: { x402Client: class {}, wrapFetchWithPayment: () => async (url) => { calls.push(url); return new Response(JSON.stringify(paidBody), { status }); } } } }; }

test("quote check: only USDC on Base to the MoneyTools wallet at or below the published price is paid", () => {
  assert.equal(verifyQuote(res402(quote(20000)), null, 0.02).amountUsd, 0.02);
  assert.throws(() => verifyQuote(res402(quote(30000)), null, 0.02), /above/);
  assert.throws(() => verifyQuote(res402(quote(20000, "0x000000000000000000000000000000000000dEaD")), null, 0.02), /payTo/);
  assert.throws(() => verifyQuote(res402(quote(20000, MONEYTOOLS_PAY_TO, "eip155:1")), null, 0.02), /Base/);
});
test("payer: key from env, else existing AgentCash wallet (existence only), else none", () => {
  assert.equal(resolvePayer({}, KEYENV, () => false).kind, "key");
  assert.equal(resolvePayer({}, {}, () => true).kind, "agentcash");
  assert.equal(resolvePayer({}, {}, () => false).kind, "none");
  assert.equal(resolvePayer({ payer: "none" }, KEYENV, () => true).kind, "none");
});
test("approve to a high-risk spender is blocked after a paid 0.02 Wallet Risk Card", async () => {
  const x = fakeX402({ level: "high", riskScore: 85, grade: "E", sanctioned: false, headline: "Risk high" });
  const g = createGuard({ autoPay: true }, { env: KEYENV, fileExists: () => false, fetch: async () => res402(quote(20000)), x402: x.mods });
  const d = await g.beforeToolCall({ toolName: "send_transaction", params: approveTx });
  assert.equal(d.block, true); assert.match(d.blockReason, /high risk/); assert.match(x.calls[0], /tools\.moneytools\.dev\/v1\/wallet-risk\?address=0x1111.*&chain=base/);
  assert.equal(g.budget.spentUsd, 0.02);
});
test("sanctioned spender is always blocked; medium asks the user; low passes", async () => {
  const a = { spender: SP, chain: "base", fn: "approve", unlimited: true }; const cfg = readConfig({});
  assert.equal(decideRisk({ ...cfg, onHighRisk: "approve" }, a, { sanctioned: true, level: "high" }).block, true);
  assert.equal(decideRisk(cfg, a, { level: "medium", riskScore: 50 }).requireApproval.severity, "warning");
  assert.equal(decideRisk(cfg, a, { level: "low", riskScore: 5 }), undefined);
});
test("x402 payment: precheck free tier (200) costs nothing; block verdict blocks; ok passes", async () => {
  let n = 0; const g = createGuard({}, { env: {}, fileExists: () => false, fetch: async (u) => { n++; return res200({ verdict: u.includes("bad") ? "block" : "ok", summary: "payTo on OFAC SDN" }); } });
  assert.equal(await g.beforeToolCall({ toolName: "agentcash__fetch", params: { url: "https://good.example/x" } }), undefined);
  const d = await g.beforeToolCall({ toolName: "agentcash__fetch", params: { url: "https://bad.example/x" } });
  assert.equal(d.block, true); assert.equal(g.budget.spentUsd, 0);
  await g.beforeToolCall({ toolName: "agentcash__fetch", params: { url: "https://good.example/x" } }); assert.equal(n, 2, "cached");
  assert.equal(decidePrecheck(readConfig({}), "u", { verdict: "warn", warnings: ["w"] }).requireApproval.title, "Pay precheck warning");
});
test("after the free tier the precheck is paid via AgentCash at 0.005", async () => {
  let ac = 0; const g = createGuard({ autoPay: true }, { env: {}, fileExists: () => true, fetch: async () => res402(quote(5000)), agentcash: async (u) => { ac++; assert.match(u, /api\.moneytools\.dev\/v1\/precheck\?url=https%3A%2F%2Fs\.example/); return { verdict: "ok" }; } });
  assert.equal(await g.beforeToolCall({ toolName: "x402_fetch", params: { url: "https://s.example/p" } }), undefined);
  assert.equal(ac, 1); assert.equal(g.budget.spentUsd, 0.005);
});
test("no wallet / budget reached / overpriced quote: nothing is paid and the user is asked (default)", async () => {
  const g = createGuard({}, { env: {}, fileExists: () => false, fetch: async () => res402(quote(20000)) });
  const d = await g.beforeToolCall({ toolName: "send_transaction", params: approveTx });
  assert.match(d.requireApproval.description, /Nothing was charged/);
  const x = fakeX402({ level: "low" }); const g2 = createGuard({ autoPay: true, dailyBudgetUsd: 0.01 }, { env: KEYENV, fileExists: () => false, fetch: async () => res402(quote(20000)), x402: x.mods });
  assert.match((await g2.beforeToolCall({ toolName: "send_transaction", params: approveTx })).requireApproval.description, /budget/); assert.equal(x.calls.length, 0);
  const g3 = createGuard({ autoPay: true, onCheckError: "block" }, { env: KEYENV, fileExists: () => false, fetch: async () => res402(quote(99000)), x402: x.mods });
  assert.equal((await g3.beforeToolCall({ toolName: "send_transaction", params: approveTx })).block, true); assert.equal(x.calls.length, 0);
});
test("a failed paid check (non-200) is reported as not charged and not counted", async () => {
  const x = fakeX402({ error: "upstream_error", message: "rpc down" }, 502);
  const g = createGuard({ autoPay: true, onCheckError: "allow" }, { env: KEYENV, fileExists: () => false, fetch: async () => res402(quote(20000)), x402: x.mods });
  assert.equal(await g.beforeToolCall({ toolName: "send_transaction", params: approveTx }), undefined); assert.equal(g.budget.spentUsd, 0);
});
test("default is opt-in: autoPay is false, cap 0.25; without autoPay nothing is ever paid", async () => {
  assert.equal(readConfig({}).autoPay, false); assert.equal(readConfig({}).dailyBudgetUsd, 0.25);
  const x = fakeX402({ level: "low" }); const g = createGuard({}, { env: KEYENV, fileExists: () => true, fetch: async () => res402(quote(20000)), x402: x.mods });
  assert.ok((await g.beforeToolCall({ toolName: "send_transaction", params: approveTx })).requireApproval); assert.equal(x.calls.length, 0);
});
test("registerGuard wires before_tool_call and two tools on an OpenClaw-like api", async () => {
  const hooks = [], tools = []; const T = { Object: (p) => ({ type: "object", properties: p }), String: (o) => ({ type: "string", ...o }), Optional: (s) => s };
  registerGuard({ pluginConfig: {}, logger: { info() {} }, on: (n, h, o) => hooks.push([n, h, o]), registerTool: (t) => tools.push(t) }, T, { env: {}, fileExists: () => false, fetch: async () => res200({ verdict: "ok" }) });
  assert.equal(hooks[0][0], "before_tool_call"); assert.deepEqual(tools.map((t) => t.name), ["moneytools_pay_precheck", "moneytools_wallet_risk"]);
  const out = await tools[0].execute("1", { url: "https://s.example/" }); assert.equal(out.details.verdict, "ok"); assert.equal(out.details.paidUsd, 0);
});
