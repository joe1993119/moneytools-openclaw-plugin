import test from "node:test"; import assert from "node:assert/strict";
import { createGuard, registerGuard, decideRisk, decidePrecheck, readConfig } from "../src/guard.js";
import { verifyQuote, verifySignedPayment, resolvePayer, makeBudget, callCheck, precheckUrl, sanitizeTargetUrl, runAgentcash, MONEYTOOLS_PAY_TO } from "../src/checks.js";
import { detectX402Payment } from "../src/detect.js";

const SP = "0x1111111254eeb25477b68fb85ed929f73a960582";
const approveTx = { data: "0x095ea7b3" + SP.slice(2).padStart(64, "0") + "f".repeat(64), chainId: 8453 };
const quote = (amount, payTo = MONEYTOOLS_PAY_TO, network = "eip155:8453") => ({ x402Version: 2, accepts: [{ scheme: "exact", network, amount: String(amount), asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo, maxTimeoutSeconds: 300 }] });
const res402 = (q) => new Response(JSON.stringify(q), { status: 402, headers: { "content-type": "application/json", "payment-required": Buffer.from(JSON.stringify(q)).toString("base64") } });
const res200 = (o) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
const KEYENV = { X402_PRIVATE_KEY: "0x" + "11".repeat(32) };
// Fake x402 client: "signs" exactly the requirement it is given (tamper() may alter the signed payload); the paid request goes through the test fetch.
function fakeX402(paidBody, status = 200, tamper = (p) => p) { const calls = []; const signed = []; return { calls, signed, mods: { accounts: { privateKeyToAccount: (k) => ({ address: "0xabc", k }) }, evm: { registerExactEvmScheme: () => {} },
  fetch: { x402Client: class {}, x402HTTPClient: class {
    async createPaymentPayload(pr) { const a = pr.accepts[0]; const p = tamper({ x402Version: 2, accepted: { ...a }, payload: { signature: "0xsig", authorization: { from: "0xabc", to: a.payTo, value: a.amount, validAfter: "0", validBefore: String(Math.floor(Date.now() / 1000) + 300), nonce: "0x01" } } }); signed.push({ pr, p }); return p; }
    encodePaymentSignatureHeader(p) { return { "PAYMENT-SIGNATURE": Buffer.from(JSON.stringify(p)).toString("base64") }; } } } },
  paidFetch: (q) => async (url, init = {}) => { if (init.headers?.["PAYMENT-SIGNATURE"]) { calls.push(url); return new Response(JSON.stringify(paidBody), { status }); } return res402(q); } }; }

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
  const g = createGuard({ autoPay: true }, { env: KEYENV, fileExists: () => false, fetch: x.paidFetch(quote(20000)), x402: x.mods });
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
test("AgentCash never pays automatically, even with autoPay on: the user is asked and nothing is paid", async () => {
  let ac = 0; const g = createGuard({ autoPay: true }, { env: {}, fileExists: () => true, fetch: async () => res402(quote(5000)), agentcash: async () => { ac++; return { verdict: "ok" }; } });
  const d = await g.beforeToolCall({ toolName: "x402_fetch", params: { url: "https://s.example/p" } });
  assert.match(d.requireApproval.description, /never charged automatically/); assert.equal(ac, 0); assert.equal(g.budget.spentUsd, 0);
  const gb = createGuard({ autoPay: true, onCheckError: "block" }, { env: {}, fileExists: () => true, fetch: async () => res402(quote(20000)), agentcash: async () => { ac++; return {}; } });
  assert.equal((await gb.beforeToolCall({ toolName: "send_transaction", params: approveTx })).block, true); assert.equal(ac, 0);
});
test("no wallet / budget reached / overpriced quote: nothing is paid and the user is asked (default)", async () => {
  const g = createGuard({}, { env: {}, fileExists: () => false, fetch: async () => res402(quote(20000)) });
  const d = await g.beforeToolCall({ toolName: "send_transaction", params: approveTx });
  assert.match(d.requireApproval.description, /Nothing was charged/);
  const x = fakeX402({ level: "low" }); const g2 = createGuard({ autoPay: true, dailyBudgetUsd: 0.01 }, { env: KEYENV, fileExists: () => false, fetch: x.paidFetch(quote(20000)), x402: x.mods });
  assert.match((await g2.beforeToolCall({ toolName: "send_transaction", params: approveTx })).requireApproval.description, /budget/); assert.equal(x.calls.length, 0);
  const g3 = createGuard({ autoPay: true, onCheckError: "block" }, { env: KEYENV, fileExists: () => false, fetch: x.paidFetch(quote(99000)), x402: x.mods });
  assert.equal((await g3.beforeToolCall({ toolName: "send_transaction", params: approveTx })).block, true); assert.equal(x.calls.length, 0);
});
test("a failed paid check (non-200) is reported as not charged and not counted", async () => {
  const x = fakeX402({ error: "upstream_error", message: "rpc down" }, 502);
  const g = createGuard({ autoPay: true, onCheckError: "allow" }, { env: KEYENV, fileExists: () => false, fetch: x.paidFetch(quote(20000)), x402: x.mods });
  assert.equal(await g.beforeToolCall({ toolName: "send_transaction", params: approveTx }), undefined); assert.equal(g.budget.spentUsd, 0);
});
test("default is opt-in: autoPay is false, cap 0.25; without autoPay nothing is ever paid", async () => {
  assert.equal(readConfig({}).autoPay, false); assert.equal(readConfig({}).dailyBudgetUsd, 0.25);
  const x = fakeX402({ level: "low" }); const g = createGuard({}, { env: KEYENV, fileExists: () => true, fetch: x.paidFetch(quote(20000)), x402: x.mods });
  assert.ok((await g.beforeToolCall({ toolName: "send_transaction", params: approveTx })).requireApproval); assert.equal(x.calls.length, 0);
});
test("registerGuard wires before_tool_call and two tools on an OpenClaw-like api", async () => {
  const hooks = [], tools = []; const T = { Object: (p) => ({ type: "object", properties: p }), String: (o) => ({ type: "string", ...o }), Boolean: (o) => ({ type: "boolean", ...o }), Optional: (s) => s };
  registerGuard({ pluginConfig: {}, logger: { info() {} }, on: (n, h, o) => hooks.push([n, h, o]), registerTool: (t) => tools.push(t) }, T, { env: {}, fileExists: () => false, fetch: async () => res200({ verdict: "ok" }) });
  assert.equal(hooks[0][0], "before_tool_call"); assert.deepEqual(tools.map((t) => t.name), ["moneytools_pay_precheck", "moneytools_wallet_risk"]);
  const out = await tools[0].execute("1", { url: "https://s.example/" }); assert.equal(out.details.verdict, "ok"); assert.equal(out.details.paidUsd, 0);
});

// --- 0.1.2: ClawHub scan findings ---
test("finding 1: the signed payment must match the verified quote (amount <= maxUsd, USDC, Base, MoneyTools payTo) or it is not sent", async () => {
  const q = verifyQuote(res402(quote(20000)), null, 0.02);
  const good = { x402Version: 2, accepted: { ...q.accept }, payload: { authorization: { to: MONEYTOOLS_PAY_TO, value: "20000", validBefore: String(Math.floor(Date.now() / 1000) + 300) } } };
  assert.equal(verifySignedPayment(good, q, 0.02), true);
  const bad = (f) => { const p = structuredClone(good); f(p); return p; };
  assert.throws(() => verifySignedPayment(bad((p) => { p.payload.authorization.value = "30000"; }), q, 0.02), /amount/);
  assert.throws(() => verifySignedPayment(bad((p) => { p.accepted.amount = "30000"; }), q, 0.02), /amount/);
  assert.throws(() => verifySignedPayment(bad((p) => { p.payload.authorization.to = "0x000000000000000000000000000000000000dEaD"; }), q, 0.02), /payTo/);
  assert.throws(() => verifySignedPayment(bad((p) => { p.accepted.payTo = "0x000000000000000000000000000000000000dEaD"; }), q, 0.02), /payTo/);
  assert.throws(() => verifySignedPayment(bad((p) => { p.accepted.asset = "0x0000000000000000000000000000000000000001"; }), q, 0.02), /asset/);
  assert.throws(() => verifySignedPayment(bad((p) => { p.accepted.network = "eip155:1"; }), q, 0.02), /network/);
  assert.throws(() => verifySignedPayment(bad((p) => { p.payload.authorization.validBefore = String(Math.floor(Date.now() / 1000) + 86400 * 365); }), q, 0.02), /window/);
  assert.throws(() => verifySignedPayment(good, q, 0.005), /cap/);
  // end to end: a client that signs different terms than quoted never gets its payment sent, and nothing is counted
  const x = fakeX402({ level: "low" }, 200, (p) => { p.payload.authorization.to = "0x000000000000000000000000000000000000dEaD"; return p; });
  const budget = makeBudget(0.25);
  await assert.rejects(callCheck("https://tools.moneytools.dev/v1/wallet-risk?address=0x1&chain=base", { maxUsd: 0.02, payer: { kind: "key", keyEnv: "X402_PRIVATE_KEY" }, env: KEYENV, fetch: x.paidFetch(quote(20000)), x402: x.mods, budget }), /bad_payment|does not match/);
  assert.equal(x.calls.length, 0); assert.equal(budget.spentUsd, 0);
  // the client is only ever offered the single verified requirement
  const x2 = fakeX402({ level: "low" }); const q2 = quote(20000); q2.accepts.push({ ...q2.accepts[0], network: "eip155:1", amount: "999999" });
  await callCheck("https://tools.moneytools.dev/v1/wallet-risk?address=0x1&chain=base", { maxUsd: 0.02, payer: { kind: "key", keyEnv: "X402_PRIVATE_KEY" }, env: KEYENV, fetch: x2.paidFetch(q2), x402: x2.mods });
  assert.equal(x2.signed[0].pr.accepts.length, 1); assert.equal(x2.signed[0].pr.accepts[0].network, "eip155:8453");
  // a second 402 after paying is a failed, uncounted check (no automatic retry)
  const x3 = fakeX402({ error: "payment_required" }, 402); const b3 = makeBudget(0.25);
  await assert.rejects(callCheck("https://tools.moneytools.dev/v1/wallet-risk?address=0x1&chain=base", { maxUsd: 0.02, payer: { kind: "key", keyEnv: "X402_PRIVATE_KEY" }, env: KEYENV, fetch: x3.paidFetch(quote(20000)), x402: x3.mods, budget: b3 }));
  assert.equal(x3.calls.length, 1); assert.equal(b3.spentUsd, 0);
});
test("finding 1 (AgentCash payer): AgentCash is limited to x402 on Base and the quoted price per request", async () => {
  let args; const fakeSpawn = (_c, a) => { args = a; const ev = {}; const p = { stdout: { on: (_e, f) => { ev.data = f; } }, on: (e, f) => { ev[e] = f; }, kill() {} }; setImmediate(() => { ev.data(JSON.stringify({ success: true, data: { verdict: "ok" } })); ev.close(); }); return p; };
  assert.deepEqual(await runAgentcash("https://api.moneytools.dev/v1/precheck?url=x", { spawnFn: fakeSpawn, maxUsd: 0.005 }), { verdict: "ok" });
  assert.deepEqual(args.slice(-6), ["--payment-protocol", "x402", "--payment-network", "base", "--max-amount", "0.005"]);
  await assert.rejects(runAgentcash("https://api.moneytools.dev/v1/precheck?url=x", { spawnFn: fakeSpawn }), /cap/);
});
test("finding 2: budget reservation is atomic; parallel paid checks cannot exceed the daily cap; failures give the reservation back", async () => {
  const b = makeBudget(0.05); const r1 = b.reserve(0.02), r2 = b.reserve(0.02), r3 = b.reserve(0.02);
  assert.ok(r1 && r2); assert.equal(r3, null); assert.equal(b.spentUsd, 0.04);
  r2.release(); r2.release(); assert.equal(b.spentUsd, 0.02); r1.commit(); r1.release(); assert.equal(b.spentUsd, 0.02);
  // 10 concurrent checks for different spenders against a 0.05 cap at 0.02 each: at most 2 are paid
  const x = fakeX402({ level: "low" }); let pending = [];
  const slowFetch = (q) => async (url, init = {}) => { await new Promise((r) => setTimeout(r, 5)); return x.paidFetch(q)(url, init); };
  const g = createGuard({ autoPay: true, dailyBudgetUsd: 0.05, onCheckError: "block" }, { env: KEYENV, fileExists: () => false, fetch: slowFetch(quote(20000)), x402: x.mods });
  for (let i = 0; i < 10; i++) { const sp = "0x" + String(i + 1).padStart(40, "0"); pending.push(g.walletRisk(sp, "base").then(() => "paid", () => "refused")); }
  const out = await Promise.all(pending);
  assert.equal(out.filter((o) => o === "paid").length, 2); assert.equal(x.calls.length, 2); assert.ok(g.budget.spentUsd <= 0.05 + 1e-9);
  // identical checks running at the same time share one payment
  const x2 = fakeX402({ level: "low" }); const g2 = createGuard({ autoPay: true }, { env: KEYENV, fileExists: () => false, fetch: x2.paidFetch(quote(20000)), x402: x2.mods });
  await Promise.all([g2.walletRisk(SP, "base"), g2.walletRisk(SP, "base"), g2.walletRisk(SP, "base")]);
  assert.equal(x2.calls.length, 1); assert.equal(g2.budget.spentUsd, 0.02);
});
test("finding 3: user info, query string and fragment never leave the agent", async () => {
  assert.equal(sanitizeTargetUrl("https://user:pass@seller.example:8443/v1/data?api_key=SECRET&sig=abc#frag"), "https://seller.example:8443/v1/data");
  assert.throws(() => sanitizeTargetUrl("file:///etc/passwd"), /http/);
  const u = precheckUrl("https://u:p@s.example/p?token=SECRET#x", "GET");
  assert.ok(!/SECRET|token|u%3Ap|%23x/.test(u)); assert.match(u, /url=https%3A%2F%2Fs\.example%2Fp&method=GET$/);
  assert.equal(detectX402Payment("x402_fetch", { url: "https://u:p@s.example/p?key=SECRET#f" }).url, "https://s.example/p");
  assert.equal(detectX402Payment("exec", { command: "npx agentcash fetch 'https://s.example/p?key=SECRET'" }).url, "https://s.example/p");
  const seen = []; const g = createGuard({}, { env: {}, fileExists: () => false, fetch: async (url) => { seen.push(url); return res200({ verdict: "ok" }); } });
  await g.beforeToolCall({ toolName: "agentcash__fetch", params: { url: "https://u:p@s.example/p?key=SECRET#f" } });
  const t = toolDefsFor(g); await t.execute("1", { url: "https://s.example/q?access_token=SECRET2" });
  assert.equal(seen.length, 2); for (const s of seen) assert.ok(!/SECRET|key%3D|access_token|u%3Ap/.test(s), s);
});
import { toolDefs } from "../src/guard.js";
const toolDefsFor = (g) => toolDefs(g, { Object: (p) => p, String: (o) => o, Boolean: (o) => o, Optional: (s) => s })[0];

// --- 0.1.3: strict combine over every approval in a call ---
import { combineDecisions } from "../src/guard.js";
const BADSP = "0x000000000000000000000000000000000000dead";
const appr = (sp) => "0x095ea7b3" + sp.slice(2).padStart(64, "0") + "f".repeat(64);
const riskFetch = (levels) => async (url) => { const sp = /address=([^&]+)/.exec(url)[1].toLowerCase(); return res200(levels[sp] || { level: "low" }); };
test("batch with one benign and one malicious approval is blocked in either order", async () => {
  for (const calls of [[{ data: appr(SP) }, { data: appr(BADSP) }], [{ data: appr(BADSP) }, { data: appr(SP) }]]) {
    const seen = []; const f = riskFetch({ [BADSP]: { level: "high", riskScore: 90, grade: "F" } });
    const g = createGuard({}, { env: {}, fileExists: () => false, fetch: async (u) => { seen.push(u); return f(u); } });
    const d = await g.beforeToolCall({ toolName: "wallet_sendCalls", params: { calls, chainId: 8453 } });
    assert.equal(d.block, true); assert.match(d.blockReason, /dead/); assert.equal(seen.length, 2, "both spenders screened");
  }
});
test("strict combine: block > ask > allow; asks are merged with the highest severity", () => {
  const ask = (t, s) => ({ requireApproval: { title: t, description: t, severity: s } });
  assert.equal(combineDecisions([undefined, ask("a", "warning"), { block: true, blockReason: "x" }]).block, true);
  const m = combineDecisions([ask("a", "warning"), undefined, ask("b", "critical")]); assert.equal(m.requireApproval.severity, "critical"); assert.match(m.requireApproval.description, /a[\s\S]*b/);
  assert.equal(combineDecisions([undefined, undefined]), undefined);
});
test("undecodable or conflicting approval content goes to onCheckError (ask by default, block when configured)", async () => {
  const params = { functionName: "approve", spender: SP, args: [BADSP, "1"] };
  const g = createGuard({}, { env: {}, fileExists: () => false, fetch: riskFetch({}) });
  assert.match((await g.beforeToolCall({ toolName: "wallet_call", params })).requireApproval.description, /disagrees/);
  const gb = createGuard({ onCheckError: "block" }, { env: {}, fileExists: () => false, fetch: riskFetch({}) });
  assert.equal((await gb.beforeToolCall({ toolName: "send_transaction", params: { data: "0x095ea7b3" + SP.slice(2).padStart(64, "0") } })).block, true);
  // one clean low-risk approval plus one undecodable one: still not silently allowed
  const d = await g.beforeToolCall({ toolName: "wallet_sendCalls", params: { calls: [{ data: appr(SP) }, { functionName: "approve", args: ["nope", "1"] }] } });
  assert.ok(d?.requireApproval);
});
test("structured Permit2 approve screens the real spender (args[1]), not the token", async () => {
  const seen = []; const g = createGuard({}, { env: {}, fileExists: () => false, fetch: async (u) => { seen.push(u); return res200({ level: "low" }); } });
  await g.beforeToolCall({ toolName: "wallet_call", params: { functionName: "approve", args: ["0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", BADSP, "10", "1800000000"] } });
  assert.equal(seen.length, 1); assert.match(seen[0], /address=0x000000000000000000000000000000000000dead/);
});

test("approve(spender, 0) to a high-risk or sanctioned spender asks (may be a revoke or an ERC-721 token #0 approval); low risk passes", async () => {
  const z = "0x095ea7b3" + BADSP.slice(2).padStart(64, "0") + "0".repeat(64);
  const g = createGuard({}, { env: {}, fileExists: () => false, fetch: riskFetch({ [BADSP]: { level: "high", riskScore: 90, grade: "F" } }) });
  const d = await g.beforeToolCall({ toolName: "send_transaction", params: { data: z } }); assert.equal(d.requireApproval.severity, "critical"); assert.match(d.requireApproval.description, /ERC-721/);
  const gs = createGuard({}, { env: {}, fileExists: () => false, fetch: riskFetch({ [BADSP]: { level: "high", sanctioned: true } }) });
  assert.match((await gs.beforeToolCall({ toolName: "send_transaction", params: { data: z } })).requireApproval.description, /OFAC/);
  const gl = createGuard({}, { env: {}, fileExists: () => false, fetch: riskFetch({}) });
  assert.equal(await gl.beforeToolCall({ toolName: "send_transaction", params: { data: z } }), undefined);
});
test("JSON-string typed data to a high-risk spender is blocked like the object form", async () => {
  const td = { primaryType: "PermitSingle", domain: { chainId: 8453 }, message: { details: {}, spender: BADSP } };
  const g = createGuard({}, { env: {}, fileExists: () => false, fetch: riskFetch({ [BADSP]: { level: "high", riskScore: 90, grade: "F" } }) });
  assert.equal((await g.beforeToolCall({ toolName: "wallet_request", params: { method: "eth_signTypedData_v4", params: [SP, JSON.stringify(td)] } })).block, true);
});

test("raw EIP-2612 permit calldata to a high-risk spender is blocked; a hex chain id is screened on that chain", async () => {
  const pd = "0xd505accf" + SP.slice(2).padStart(64, "0") + BADSP.slice(2).padStart(64, "0") + "a".padStart(64, "0") + "f".repeat(64) + "1b".padStart(64, "0") + "ab".repeat(32) + "cd".repeat(32);
  const seen = []; const f = riskFetch({ [BADSP]: { level: "high", riskScore: 90, grade: "F" } });
  const g = createGuard({}, { env: {}, fileExists: () => false, fetch: async (u) => { seen.push(u); return f(u); } });
  assert.equal((await g.beforeToolCall({ toolName: "send_transaction", params: { data: pd, chainId: "0x1" } })).block, true);
  assert.match(seen[0], /chain=ethereum/);
  const d = await g.beforeToolCall({ toolName: "send_transaction", params: { data: pd, chainId: "0x1234567" } }); assert.ok(d.requireApproval); assert.match(d.requireApproval.description, /unsupported chain/);
});

// --- 0.1.6: AgentCash pays only after a per-check user confirmation; every approval judged separately ---
const T6 = { Object: (p) => p, String: (o) => o, Boolean: (o) => o, Optional: (s) => s };
test("AgentCash: a paid check runs only after OpenClaw reports allow-once for that exact tool call; deny, timeout or no hook pays nothing", async () => {
  let ac = 0; const g = createGuard({}, { env: {}, fileExists: () => true, fetch: async () => res402(quote(20000)), agentcash: async (u, o) => { ac++; assert.equal(o.maxUsd, 0.02); return { level: "low" }; } });
  const tool = toolDefs(g, T6)[1]; const params = { address: SP, chain: "base", payWithAgentcash: true };
  // without the hook / confirmation: refused, nothing paid
  assert.equal((await tool.execute("call-1", params)).details.error, "confirm_required"); assert.equal(ac, 0);
  // hook asks; deny -> refused
  const ask = await g.beforeToolCall({ toolName: "moneytools_wallet_risk", params, toolCallId: "call-2" });
  assert.match(ask.requireApproval.description, /0\.02 USDC/); assert.deepEqual(ask.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  await ask.requireApproval.onResolution("deny"); assert.equal((await tool.execute("call-2", params)).details.error, "confirm_required"); assert.equal(ac, 0);
  // allow-once -> exactly one paid check for that call id; a second run of the same id is refused
  const ok = await g.beforeToolCall({ toolName: "moneytools_wallet_risk", params, toolCallId: "call-3" }); await ok.requireApproval.onResolution("allow-once");
  assert.equal((await tool.execute("call-4", params)).details.error, "confirm_required", "grant is bound to its own call id");
  const r = await tool.execute("call-3", params); assert.equal(r.details.level, "low"); assert.equal(r.details.paidUsd, 0.02); assert.equal(ac, 1); assert.equal(g.budget.spentUsd, 0.02);
  assert.equal((await tool.execute("call-3", { ...params, address: BADSP })).details.error, "confirm_required"); assert.equal(ac, 1);
  // expired confirmation
  let t = 0; const g2 = createGuard({}, { env: {}, now: () => t, fileExists: () => true, fetch: async () => res402(quote(5000)), agentcash: async () => { ac++; return { verdict: "ok" }; } });
  const p2 = { url: "https://s.example/p", payWithAgentcash: true }; const a2 = await g2.beforeToolCall({ toolName: "moneytools_pay_precheck", params: p2, toolCallId: "c" }); await a2.requireApproval.onResolution("allow-once");
  t = 10 * 60000; assert.equal((await toolDefs(g2, T6)[0].execute("c", p2)).details.error, "confirm_required"); assert.equal(ac, 1);
  // key wallet + autoPay still pays automatically
  const x = fakeX402({ level: "low" }); const gk = createGuard({ autoPay: true }, { env: KEYENV, fileExists: () => true, fetch: x.paidFetch(quote(20000)), x402: x.mods });
  assert.equal(await gk.beforeToolCall({ toolName: "send_transaction", params: approveTx }), undefined); assert.equal(x.calls.length, 1);
});
test("every approval is judged on its own: zero-then-unlimited to a high-risk spender is blocked in either order, with one risk lookup", async () => {
  const zero = "0x095ea7b3" + BADSP.slice(2).padStart(64, "0") + "0".repeat(64); const unl = appr(BADSP);
  for (const calls of [[{ data: zero }, { data: unl }], [{ data: unl }, { data: zero }]]) {
    const seen = []; const f = riskFetch({ [BADSP]: { level: "high", riskScore: 90, grade: "F" } });
    const g = createGuard({}, { env: {}, fileExists: () => false, fetch: async (u) => { seen.push(u); return f(u); } });
    const d = await g.beforeToolCall({ toolName: "wallet_sendCalls", params: { calls, chainId: 8453 } });
    assert.equal(d.block, true); assert.match(d.blockReason, /UNLIMITED/); assert.equal(seen.length, 1, "one lookup per spender");
  }
  // sanctioned spender: positive grant blocked even next to a zero-amount op
  const gs = createGuard({}, { env: {}, fileExists: () => false, fetch: riskFetch({ [BADSP]: { level: "high", sanctioned: true } }) });
  assert.equal((await gs.beforeToolCall({ toolName: "wallet_sendCalls", params: { calls: [{ data: zero }, { data: "0x095ea7b3" + BADSP.slice(2).padStart(64, "0") + "5".padStart(64, "0") }] } })).block, true);
});
test("approvals to the same spender on different tokens are all kept and named in the decision", async () => {
  const T1 = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", T2 = "0x4200000000000000000000000000000000000006";
  const g = createGuard({ onMediumRisk: "approve" }, { env: {}, fileExists: () => false, fetch: riskFetch({ [BADSP]: { level: "medium", riskScore: 50 } }) });
  const d = await g.beforeToolCall({ toolName: "wallet_sendCalls", params: { calls: [{ to: T1, data: appr(BADSP) }, { to: T2, data: "0x095ea7b3" + BADSP.slice(2).padStart(64, "0") + "64".padStart(64, "0") }] } });
  assert.match(d.requireApproval.title, /2 checks/); assert.match(d.requireApproval.description, new RegExp(T1)); assert.match(d.requireApproval.description, new RegExp(T2)); assert.match(d.requireApproval.description, /UNLIMITED/); assert.match(d.requireApproval.description, /of 100/);
});
