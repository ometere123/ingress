# Ingress Studionet Deployment

Source commit:
`594d32439eb67af666bc69935ff161ababc58741`

Date:
2026-08-17

Network:
Studionet

RPC:
`https://studio.genlayer.com/api`

Deployment method:
official genlayer-test Studio Mode (`genlayer-test 0.29.2`, Python `3.12.13`)

Deployer:
`0x62eBa06A7fCbba23271EeFcAe1EebE99B45EADc3`

Contract:
`0x86506D4017B5B47Ce8Cd03b3C561E3bd96cfA0e5`

Deployment transaction:
`0x277e11d40d3247b423017b12d47be884ccf5630a4bd6eb45942a184969f1dc72`

Status:
`FINALIZED`, `MAJORITY_AGREE`

## Source parity

The deployed source is commit `594d324`.

`contracts/ingress.py` has not changed after that deployment source commit. Subsequent repository commits affect only tests, tooling dependencies, fixtures and documentation; the deployable contract source remains identical.

All runtime transactions below target the lint-clean deployment above. The earlier pre-linter safe/hostile transactions are historical and intentionally omitted from this current-runtime table.

The committed `tests/integration/test_ingress_studionet.py` suite independently redeploys the unchanged contract through official Studio Mode for reproducibility; those disposable test deployments do not replace the canonical address recorded above.

## Runtime verification

| Action | Transaction | Result |
|---|---|---|
| Schema | — | PASS; all expected Ingress methods present, including `open_inspection`, `resolve`, `cancel`, `get_capsule`, `is_consumable`, and `get_risk_dictionary` |
| Deployed code | — | PASS; CLI returned the deployed Python source matching the deployment source commit |
| `get_risk_dictionary()` | — | PASS; all 10 expected diagnostic bits returned |
| Open safe inspection | `0x6904fced0e3e692192a65413dd417bed99acce7ac65c6b1dd2c3160447cac224` | PASS; capsule `1`, `PENDING` |
| Safe resolve | `0x47703a64c766f1955452b8863cd0988982e04008c310df939737e8459ee095ea` | PASS; capsule `1`, `SAFE`, risk mask `0`, grounded excerpt returned |
| Safe `is_consumable(1)` | — | `true` |
| Open cancellation inspection | `0xdb80094dfb070ced1b1247f1c8779f67a05e17744777533b01f4f5b85fa96482` | PASS; capsule `2` |
| Cancel capsule | `0x56e7e14c9826dd5c4c386a528cbd7d8afdfc6bf40e25bceb1a5990d8a24f6052` | PASS; capsule `2`, `CANCELLED` |
| Open hostile inspection | `0x33dbc89ace583008e17c3982733d5368eae558adccb3940912e331db7367e959` | PASS; capsule `3` |
| Hostile resolve | `0x1b0c6f3d6f4cf6d5385f5407d622a5c16d2b9dda5fffeef9fbb762ea4d9d450a` | PASS; capsule `3`, `QUARANTINED`, risk mask `265` (`PROMPT_OVERRIDE`, `SECRET_EXFILTRATION`, `LITERAL_CONTROL_PHRASE`) |
| Hostile `is_consumable(3)` | — | `false` |

The hostile source was the public fixture added at commit `daf1fc1`:
`https://raw.githubusercontent.com/ometere123/ingress/main/fixtures/hostile_evidence.txt`

## Receipt and trace notes

The first inspection attempt used CLI arguments prefixed with `str:`. The CLI encoded those prefixes literally, so the contract correctly rejected `str:https://example.com` with `EXPECTED: only https urls are accepted`. Failed transaction:
`0x1f55a77db54e15fadab7fbe21b7f785097bac06f3963578cc8e2b65fdc24a94c`.

Its receipt reached `ACCEPTED` with the contract rollback payload. The CLI trace request was also attempted, but Studionet returned `Method not found: gen_dbg_traceTransaction`; the receipt contained the complete rollback reason. Retrying with plain string arguments succeeded.

The fresh safe and hostile resolve receipts reached `ACCEPTED` / `MAJORITY_AGREE`; the resulting capsules were respectively `SAFE` and `QUARANTINED`, with consumption results `true` and `false`.
