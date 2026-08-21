# Ingress Studionet Deployment

Source commit:
`1dd86da00fff84344d3ff54e194c4b273ff013f1`

Date:
2026-08-21

Network:
Studionet

RPC:
`https://studio.genlayer.com/api`

Deployment method:
official GenLayer CLI `0.39.2` via `scripts/deploy_studionet.py`

Deployer:
`0xb5ecd6dda36b370aca4af5e2005d8e2ae89c6db2`

Contract:
`0xdd641B5bdBE8D9C14783b458425da180946Fe41c`

Deployment transaction:
`0x4e3dda328e0bfc325e45497944fd9c71b7ed898bc92571eba4bf0d12283b3b70`

Status:
`FINALIZED`, `MAJORITY_AGREE`

## Why this address replaces the previous one

The first submission was deployed at `0x86506D4017B5B47Ce8Cd03b3C561E3bd96cfA0e5` from source commit `594d3243`. That deployment predates the validator excerpt-availability binding added in response to the steward review, so its bytecode is superseded and its transaction evidence no longer describes the current consensus rules.

The address above is a fresh deployment of the fixed contract. The earlier address is retained in history for audit purposes only and should not be used as current evidence.

## Source parity

The deployed source is commit `1dd86da`.

Parity was verified directly against the chain rather than asserted:

```bash
genlayer code 0xdd641B5bdBE8D9C14783b458425da180946Fe41c --rpc https://studio.genlayer.com/api
```

The returned source is byte-for-byte identical to `contracts/ingress.py` at this commit (`sha256:a53fba4d8d6d2615e0a6d2e59d0a0863c6ca36dd55141195a958f3baaf91acbc`). The chain copy contains `judge_excerpt_release` and `excerpts_for_class` at the same occurrence counts as the local file, including the `risk_class(own_mask) != STATUS_SAFE` guard in `validator_fn`.

The committed `tests/integration/test_ingress_studionet.py` suite independently redeploys this same contract through official Studio Mode for reproducibility; those disposable test deployments do not replace the canonical address recorded above.

## Runtime verification

| Action | Transaction | Result |
|---|---|---|
| Schema | — | PASS; all six Ingress methods present — `open_inspection`, `resolve`, `cancel`, `get_capsule`, `is_consumable`, `get_risk_dictionary` |
| Deployed code | — | PASS; CLI returned deployed source byte-identical to the deployment source commit |
| Open safe inspection | `0xda1c8e5a5d71e7aa3e20651f7e8661c435cea0137311bd00333ef013297d4535` | PASS; capsule `4`, `PENDING` |
| Safe resolve | `0xe14bc74309ca33ef4ee4a9d818a62aeb47337c6469c6ce90ee20292ac283463c` | PASS; capsule `4`, `SAFE`, risk mask `0`, grounded excerpt returned, `MAJORITY_AGREE` |
| Safe `is_consumable(4)` | — | `true` |
| Earlier safe resolve | `0x3cbf2a3be553f54eb63eb708c47474adea975207f938066c94b2616847e27174` | PASS; capsule `1`, `SAFE`, risk mask `0`, grounded excerpt, `FINALIZED` / `MAJORITY_AGREE` |
| Safe `is_consumable(1)` | — | `true` |
| Open cancellation inspection | `0xd9e5ff985de6b639e78668c1dd1bb30d8d62ee7784cb7364d54ac532688ec306` | PASS; capsule `2`, `PENDING` |
| Cancel capsule | `0xe0eef17a801d7ab47e24a27a73e94e1e375f7ce4a000a334f2c3f64076ef94c9` | PASS; capsule `2`, `CANCELLED`, `FINALIZED` |
| Open hostile inspection | `0x267c390ddfd28c93e820f37b2f85b0c15a327d51632a5394eea21a89f6b93b84` | PASS; capsule `3`, `PENDING` |
| Hostile resolve | `0x51f620aed7343bcd54d0c7a8561ceaeb82e4a58f07d462e9caa8511a17adb537` | PASS; capsule `3`, `QUARANTINED`, risk mask `265` (`PROMPT_OVERRIDE`, `SECRET_EXFILTRATION`, `LITERAL_CONTROL_PHRASE`), `FINALIZED` |
| Hostile `is_consumable(3)` | — | `false` |
| Hostile evidence suppression | — | PASS; capsule `3` stored `excerpts: []` despite a `QUARANTINED` classification, confirming `excerpts_for_class` live |

The hostile source is the public repository fixture:
`https://raw.githubusercontent.com/ometere123/ingress/main/fixtures/hostile_evidence.txt`

## Live evidence for the availability binding

The safe resolutions are the load-bearing new evidence. Under the previous contract a leader could have returned an empty excerpt list for `https://example.com/` and produced a `SAFE` but non-consumable capsule with no validator objecting.

On this deployment both safe resolutions reached `MAJORITY_AGREE` **with** a grounded excerpt and `is_consumable == true`. Five validators independently rendered and classified the source, independently judged the proposed excerpt releasable, and independently agreed that releasable evidence existed. Consumability here is a consensus observation, not a leader preference.

These runs also demonstrate the boundary that [`SECURITY.md`](SECURITY.md) states explicitly. Capsule `1` settled on the excerpt:

```text
This domain is for use in documentation examples without needing permission.
```

while capsule `4` settled on:

```text
This domain is for use in documentation examples without needing permission. Avoid use in operations.
```

Both are grounded, passive, relevant and validator-approved. The binding constrains whether releasable evidence *existed*, not which releasable span a leader chose — and every choice is independently grounded and judged before it can settle.

## Receipt and trace notes

All recorded resolutions reached `MAJORITY_AGREE`. The safe resolves, the cancellation and the hostile resolve were each confirmed `FINALIZED` by `genlayer receipt`.

Validator participation on this network includes `IDLE` validators in some rounds (for example `AGREE, AGREE, AGREE, IDLE, IDLE` on the deployment transaction). That is Studionet validator availability, not disagreement; `result_name` remained `MAJORITY_AGREE` throughout and no round required rotation.

Studionet does not expose `gen_dbg_traceTransaction`; receipts carried complete result payloads, so no trace request was required.
