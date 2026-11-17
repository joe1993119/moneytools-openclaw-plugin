# MoneyTools Guard for OpenClaw

`@moneytools-dev/openclaw-plugin` adds two automatic checks to an OpenClaw agent:

| When | Check | Cost |
|---|---|---|
| Before any x402 payment | [Pay precheck](https://api.moneytools.dev/v1/precheck): validates the seller's 402 terms (network, amount, asset, payTo) and screens payTo against the OFAC SDN list | free daily tier, then 0.005 USDC |
| Before any token approval (ERC-20 `approve` / `increaseAllowance`, `setApprovalForAll`, Permit2 `approve`, Permit/Permit2 signatures) | [Wallet Risk Card](https://tools.moneytools.dev/v1/wallet-risk) on the spender: 0-100 risk score, grade A-F, OFAC SDN match, address checks, open approvals | 0.02 USDC |

Paid checks are **opt-in** (`autoPay: true`); by default the plugin uses only the free tier and asks you when a check would need payment. When enabled, checks are paid in USDC on Base from the agent's own wallet. There is no MoneyTools account or API key. MoneyTools does not settle a payment when a check fails, so failed checks are not charged.

## Install (one line)

```bash
openclaw plugins install @moneytools-dev/openclaw-plugin && openclaw plugins enable moneytools-guard
```

To let it pay for checks automatically (opt-in, capped at 0.25 USDC/day by default):

```bash
openclaw config set plugins.entries.moneytools-guard.config.autoPay true
```

From npm instead of ClawHub: `openclaw plugins install npm:@moneytools-dev/openclaw-plugin`.

The plugin is off until you enable it, and it spends nothing until you set `autoPay: true`.

## What it spends, and from which wallet

- **Payer** (`payer: "auto"`): the EVM key in `X402_PRIVATE_KEY` if set (the same variable AgentCash and x402 clients use), otherwise an existing AgentCash wallet (`~/.agentcash/wallet.json`, paid through the pinned `agentcash@0.17.1` CLI). The plugin never reads the AgentCash wallet file; it only checks that it exists. If neither is present, only the free tier is used.
- **Price guard**: before paying, the plugin reads the 402 quote and pays only if it is USDC on Base, payTo is the MoneyTools wallet `0x64eB63904Cf9688AC5B3087A72AcF9C31a273169`, and the amount is at most the published price (0.005 or 0.02 USDC).
- **Daily cap**: `dailyBudgetUsd` (default 0.25 USDC per UTC day, max 5).
- **Cache**: the same URL or spender is not checked again for `cacheMinutes` (default 10).
- `autoPay` (default `false`): with `false` the plugin never pays; precheck uses its free daily tier, and a check that needs payment (always the Wallet Risk Card) goes to `onCheckError`, which asks you by default.

## What it decides

| Result | Default action | Config |
|---|---|---|
| Precheck `ok` | continue | |
| Precheck `warn` | ask you (OpenClaw approval) | `onPrecheckWarn`: approve / allow / block |
| Precheck `block` | block the payment | |
| Spender on OFAC SDN | block (always) | |
| Spender risk `high` | block | `onHighRisk`: block / approve |
| Spender risk `medium` | ask you | `onMediumRisk`: approve / allow / block |
| Check could not run (no wallet, cap reached, network) | ask you; nothing is charged | `onCheckError`: approve / allow / block |

## How payments and approvals are detected

The plugin uses OpenClaw's `before_tool_call` hook.

- **x402 payment**:
  - a tool whose name matches x402 / agentcash / pay / paid_fetch (`paymentToolPattern` to change) and has a URL;
  - any tool call that carries a `PAYMENT-SIGNATURE` or `X-PAYMENT` header;
  - an `exec` command running `agentcash fetch <url>` or sending a payment header.
- **Approval**:
  - calldata with the `approve`, `increaseAllowance`, `setApprovalForAll(true)` or Permit2 `approve` selector;
  - structured `{ functionName: "approve", args: [spender, ...] }` calls;
  - EIP-712 `Permit` / `PermitSingle` / `PermitBatch` signatures;
  - `cast send ... "approve(address,uint256)" <spender>`.
- `approve(spender, 0)` is a revoke and is not checked. MoneyTools' own check URLs are never checked, so the plugin cannot loop.

## Tools for the agent

- `moneytools_pay_precheck { url, method? }`
- `moneytools_wallet_risk { address, chain? }`, where chain is one of base, ethereum, arbitrum, optimism, polygon, bsc or avalanche.

## Config example (`openclaw.json`)

```json
{ "plugins": { "entries": { "moneytools-guard": { "enabled": true, "config": { "autoPay": true, "dailyBudgetUsd": 0.1, "onMediumRisk": "allow" } } } } }
```

## No OpenClaw? One line with AgentCash

```bash
npx agentcash fetch "https://tools.moneytools.dev/v1/wallet-risk?address=vitalik.eth&chain=base"
npx agentcash fetch "https://api.moneytools.dev/v1/precheck?url=https://example.com/paid&method=GET"
```

## Tests

Run `npm test`. The tests make no network calls and spend nothing. The x402 signing test uses a random throwaway key against a local server.

## Support

MoneyTools Team, support@moneytools.dev, https://moneytools.dev/products/payment-safety/. MIT license.
