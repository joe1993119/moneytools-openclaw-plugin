// Loads index.js through the real OpenClaw SDK when it is installed (peer dependency); skipped otherwise.
import test from "node:test"; import assert from "node:assert/strict"; import { readFileSync } from "node:fs";
let sdk = null; try { sdk = await import("openclaw/plugin-sdk/plugin-entry"); } catch {}
test("manifest and package metadata agree", () => {
  const m = JSON.parse(readFileSync(new URL("../openclaw.plugin.json", import.meta.url))); const p = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));
  assert.equal(m.id, "moneytools-guard"); assert.equal(m.version, p.version); assert.deepEqual(p.openclaw.extensions, ["./index.js"]);
  assert.deepEqual(m.contracts.tools, ["moneytools_pay_precheck", "moneytools_wallet_risk"]); assert.equal(m.enabledByDefault, false); assert.equal(m.configSchema.properties.autoPay.default, false); assert.equal(m.configSchema.properties.dailyBudgetUsd.default, 0.25);
});
test("entry: definePluginEntry from the real SDK registers the hook and tools", { skip: !sdk && "openclaw not installed" }, async () => {
  const entry = (await import("../index.js")).default; assert.equal(entry.id, "moneytools-guard");
  const hooks = [], tools = []; entry.register({ pluginConfig: { autoPay: false }, logger: { info() {}, warn() {} }, on: (n, h, o) => hooks.push([n, o]), registerTool: (t) => tools.push(t) });
  assert.equal(hooks[0][0], "before_tool_call"); assert.equal(tools.length, 2); assert.equal(tools[1].parameters.type, "object");
});
