// Real @x402/fetch + @x402/evm + viem signing against a LOCAL fake seller (random throwaway key, nothing settles, no network).
import test from "node:test"; import assert from "node:assert/strict"; import http from "node:http";
import { generatePrivateKey } from "viem/accounts";
import { callCheck, resolvePayer, makeBudget, MONEYTOOLS_PAY_TO } from "../src/checks.js";
test("key payer: real x402 v2 client signs our 402 quote and retries with PAYMENT-SIGNATURE", async () => {
  let sig = null;
  const srv = http.createServer((req, res) => {
    const url = `http://127.0.0.1:${srv.address().port}${req.url}`;
    const q = { x402Version: 2, error: "payment required", resource: { url, description: "test", mimeType: "application/json" },
      accepts: [{ scheme: "exact", network: "eip155:8453", amount: "20000", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: MONEYTOOLS_PAY_TO, maxTimeoutSeconds: 300, extra: { name: "USD Coin", version: "2" } }] };
    if (req.headers["payment-signature"]) { sig = JSON.parse(Buffer.from(req.headers["payment-signature"], "base64").toString()); res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ level: "low", riskScore: 3 })); }
    res.writeHead(402, { "content-type": "application/json", "payment-required": Buffer.from(JSON.stringify(q)).toString("base64") }); res.end(JSON.stringify(q));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const env = { X402_PRIVATE_KEY: generatePrivateKey() }; const budget = makeBudget(0.25);
    const out = await callCheck(`http://127.0.0.1:${srv.address().port}/v1/wallet-risk?address=0x1&chain=base`, { maxUsd: 0.02, payer: resolvePayer({}, env, () => false), env, budget });
    assert.equal(out.data.level, "low"); assert.equal(out.paidUsd, 0.02); assert.equal(budget.spentUsd, 0.02);
    assert.equal(sig.x402Version, 2); assert.equal(sig.accepted.payTo, MONEYTOOLS_PAY_TO); assert.equal(sig.accepted.amount, "20000");
    assert.equal(sig.payload.authorization.to.toLowerCase(), MONEYTOOLS_PAY_TO.toLowerCase()); assert.equal(sig.payload.authorization.value, "20000");
  } finally { srv.close(); }
});
