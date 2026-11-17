// MoneyTools Guard for OpenClaw: pay precheck before every x402 payment, Wallet Risk Card before every token approval.
import { Type } from "typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerGuard, PLUGIN_ID } from "./src/guard.js";

export default definePluginEntry({
  id: PLUGIN_ID,
  name: "MoneyTools Guard",
  description: "Before an agent pays an x402 seller, runs the MoneyTools pay precheck (0.005 USDC); before it approves a token spender, runs the Wallet Risk Card (0.02 USDC) and blocks high-risk or sanctioned spenders. Paid from the agent's own wallet; failed checks are not charged.",
  register(api) { registerGuard(api, Type); },
});
