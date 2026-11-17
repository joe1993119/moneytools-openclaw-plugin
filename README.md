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

To let it pay for checks automatically from the agent's key wallet (`X402_PRIVATE_KEY`; opt-in, capped at 0.25 USDC/day by default):

```bash
openclaw config set plugins.entries.moneytools-guard.config.autoPay true
```

From npm instead of ClawHub: `openclaw plugins install npm:@moneytools-dev/openclaw-plugin`.

The plugin is off until you enable it, and it spends nothing until you set `autoPay: true`.

## What it spends, and from which wallet

- **Payer** (`payer: "auto"`): the EVM key in `X402_PRIVATE_KEY` if set (the same variable AgentCash and x402 clients use), otherwise an existing AgentCash wallet (`~/.agentcash/wallet.json`, paid through the pinned `agentcash@0.17.1` CLI). The plugin never reads the AgentCash wallet file; it only checks that it exists. If neither is present, only the free tier is used.
- **Automatic payment uses the key wallet only.** With `autoPay: true`, checks after the free tier are paid automatically only from `X402_PRIVATE_KEY`, where the plugin verifies the signed payment itself (below).
- **AgentCash never pays automatically.** AgentCash signs inside its own process, so its payment cannot be bound to the quote the plugin verified. With an AgentCash wallet, automatic checks use the free tier; when a check needs payment you are asked (per `onCheckError`) and nothing is paid. To pay one check from AgentCash, the agent calls `moneytools_wallet_risk` or `moneytools_pay_precheck` with `payWithAgentcash: true`; OpenClaw then asks you to confirm that single payment (allow once / deny). The confirmation is bound to that tool call, used once, and expires after 2 minutes; AgentCash is still limited to x402 on Base and the published price (`--max-amount`).
- **Price guard**: before paying, the plugin reads the 402 quote and pays only if it is USDC on Base, payTo is the MoneyTools wallet `0x64eB63904Cf9688AC5B3087A72AcF9C31a273169`, and the amount is at most the published price (0.005 or 0.02 USDC).
- **Signed-payment check**: with a key payer, the plugin signs only the single verified requirement, then checks the signed authorization (amount, USDC, Base, payTo, validity window) against the quote before sending it. One paid request, no automatic retry.
- **Daily cap**: `dailyBudgetUsd` (default 0.25 USDC per UTC day, max 5). Spend is reserved before each payment starts, so parallel checks cannot exceed the cap; a payment that does not complete gives its reservation back. Identical checks running at the same time share one payment.
- **What comes back**: MoneyTools responses are validated against a fixed schema per endpoint. Only typed fields reach decisions, logs and the agent: verdict, risk score, grade, level, sanctioned, and reason, warning and flag codes. Upstream free text (summaries, headlines, flag details, labels) is dropped, and short summaries are rebuilt locally from the codes. A malformed response follows `onCheckError`.
- **What is sent**: only the scheme, host, port and path of the URL being checked. User info, query strings and fragments (API keys, signed links) are dropped before the precheck request and are not logged.
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
  - calldata with the `approve`, `increaseAllowance`, `setApprovalForAll(true)`, EIP-2612 `permit`, DAI `permit`, Permit2 `approve`, or Permit2 `permit` (single and batch) selector;
  - structured calls decoded by their ABI: `approve` / `increaseAllowance(spender, amount)`, `setApprovalForAll(operator, true)`, EIP-2612 `permit` (spender = `args[1]`), Permit2 `approve(token, spender, amount, expiration)` (spender = `args[1]`);
  - EIP-712 signatures, as objects or JSON strings (including `eth_signTypedData_v4` requests): EIP-2612 / DAI `Permit` and every Permit2 type (`PermitSingle`, `PermitBatch`, `PermitTransferFrom`, `PermitBatchTransferFrom`, `PermitWitnessTransferFrom`, `PermitBatchWitnessTransferFrom`). The domain is checked (Permit2 types must use the canonical Permit2 contract; EIP-2612 permits must name the token), and the types must define the primary type. Unknown Permit2 or permit-like types follow `onCheckError`; other typed data that names a `spender` is still screened;
  - `cast send ... "approve(address,uint256)" <spender>`.
- **Every approval in a call is screened**, including nested and batched transactions (`calls`, `transactions`, multicall `bytes[]`). The Wallet Risk Card is fetched once per spender, but every approval is judged on its own (amount, unlimited, token, revoke status): a positive grant never inherits the softer treatment of a zero-amount operation next to it. The results are combined strictly: if any approval is blocked the whole call is blocked; otherwise, if any needs your OK, you are asked once with every reason.
- Approval content that cannot be fully decoded (truncated calldata, tightly packed batches such as Safe `multiSend`, unparsed `cast` commands, very deep or very large batches), or whose explicit fields disagree with the call arguments or calldata, is never treated as screened: it follows `onCheckError` (ask by default).
- **Chain**: chain ids are read the same way everywhere (names, decimal or hex ids, `eip155:N`). The configured `defaultChain` is used only when no chain is given. An unsupported chain id, or chain ids that disagree, follow `onCheckError`; screening never runs on a guessed network.
- Only certain revokes are skipped: `setApprovalForAll(operator, false)`, approvals to the zero address, and a DAI permit with `allowed: false` whose signed type is exactly DAI's `Permit(holder, spender, nonce, expiry, bool allowed)` (an `allowed` property that is not part of the signed type is ignored). `approve(spender, 0)` with a non-zero spender is ambiguous (an ERC-20 revoke, or an ERC-721 approval of token #0), so the spender is still screened; for a risky or sanctioned spender you are asked instead of the call being blocked, since it may be a revoke. MoneyTools' own check URLs are never checked, so the plugin cannot loop.

Detection is heuristic. It covers the formats above; it is not a replacement for wallet-level transaction and signing controls.

## Tools for the agent

- `moneytools_pay_precheck { url, method?, payWithAgentcash? }`
- `moneytools_wallet_risk { address, chain?, payWithAgentcash? }`, where chain is one of base, ethereum, arbitrum, optimism, polygon, bsc or avalanche.

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

## Changelog

- **0.1.8**: a permit is treated as a DAI revoke only when its signed type declares `allowed` as a bool in DAI's Permit format; otherwise it is screened.
- **0.1.7**: Permit2 witness transfers screened; EIP-712 domain and type definitions validated; unknown permit-like typed data follows `onCheckError`. MoneyTools responses validated and reduced to allowlisted fields before use.
- **0.1.6**: AgentCash never pays automatically (key-wallet autoPay unchanged); an AgentCash-paid check needs a per-call user confirmation. Risk is looked up once per spender, but every approval is judged separately.
- **0.1.5**: one chain-id normalizer (hex, decimal, CAIP-2); unsupported or conflicting chain ids follow `onCheckError`; raw EIP-2612, DAI and Permit2 `permit` calldata is decoded and screened.
- **0.1.4**: `approve(spender, 0)` is screened (may be ERC-721 token #0); JSON-string typed data and `eth_signTypedData_v4` requests are parsed and screened; unreadable signing payloads follow `onCheckError`.
- **0.1.3**: every approval in a call is screened (nested and batched), strict combine of results, Permit2 `approve` decoded by its ABI, undecodable or conflicting approval content follows `onCheckError`.
- **0.1.2**: signed payments are checked against the verified quote before sending; atomic daily-budget reservation; user info, query and fragment stripped from checked URLs.
- **0.1.1**: paid checks opt-in (`autoPay` default false), 0.25 USDC/day cap.

## Support

MoneyTools Team, support@moneytools.dev, https://moneytools.dev/products/payment-safety/. MIT license.
