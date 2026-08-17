# Ingress Studionet Deployment

Source commit:
`75a965eaa8760c26fe86fa8918c690ca150702ae`

Date:
2026-08-17

Network:
Studionet

RPC:
`https://studio.genlayer.com/api`

Deployment method:
GenLayer CLI `0.39.2`

Deployer:
`0x494e6F2370e481e51284C1A8DC5649A7fA50e8a6`

Contract:
`0xd7fe4E83829E357CB192071F05Fa5416A1ae485F`

Deployment transaction:
`0xa9091bd32f5f3b5d5de3c17ce1b04c3545cd1d46df79dbdfbf02acd48bc2605b`

Status:
`FINALIZED`, `MAJORITY_AGREE`

## Source parity

The deployed source is commit `75a965eaa8760c26fe86fa8918c690ca150702ae`.

`contracts/ingress.py` has not changed after that deployment source commit. Subsequent repository commits add the hostile evidence fixture and reviewer/deployment documentation only, so the deployable contract on current `main` remains byte-identical to the contract that was deployed and smoke-tested below.

## Runtime verification

| Action | Transaction | Result |
|---|---|---|
| Schema | — | PASS; all expected Ingress methods present, including `open_inspection`, `resolve`, `cancel`, `get_capsule`, `is_consumable`, and `get_risk_dictionary` |
| Deployed code | — | PASS; CLI returned the deployed Python source matching the deployment source commit |
| `get_risk_dictionary()` | — | PASS; all 10 expected diagnostic bits returned |
| Open safe inspection | `0x32fdf3fcfd9c53d49730a3757d9f3b26311e75aa7feeeb7f06c6eec5f10185d2` | PASS; capsule `1`, `PENDING` |
| Read pending capsule | — | PASS; status `0`, empty excerpts, `consumable: false` |
| Open cancellation inspection | `0x7ed99a4ca79c225ebd067e08e4b4e309c1314c6c0129943d5287fc01eb3f654b` | PASS; capsule `2`, `PENDING` |
| Cancel capsule | `0x329f7e3460faf666899ebc3c4ed827129e23a8fc36f2063e9e82034814970195` | PASS; capsule `2`, `CANCELLED` |
| Safe resolve | `0xd72c3bd2817b62ce6c6231b1e5d88d081a63187e96a459f92169ff88c14bbc03` | PASS; capsule `1`, `SAFE`, risk mask `0`, two grounded excerpts |
| Safe `is_consumable(1)` | — | `true` |
| Open hostile inspection | `0xfa6a8fd965f0b06c4e1dcff99f421de673a2b9bc698e57fa14510ffc6dc2d5ac` | PASS; capsule `3`, `PENDING` |
| Hostile resolve | `0xa2b2c6fb4c858016098b94f190e3c87e5b4d1274ad8ff49eb459bd43a2f76d51` | PASS; capsule `3`, `QUARANTINED`, risk mask `265` (`PROMPT_OVERRIDE`, `SECRET_EXFILTRATION`, `LITERAL_CONTROL_PHRASE`) |
| Hostile `is_consumable(3)` | — | `false` |

The hostile source was the public fixture added at commit `daf1fc1`:
`https://raw.githubusercontent.com/ometere123/ingress/main/fixtures/hostile_evidence.txt`

## Receipt and trace notes

The first inspection attempt used CLI arguments prefixed with `str:`. The CLI encoded those prefixes literally, so the contract correctly rejected `str:https://example.com` with `EXPECTED: only https urls are accepted`. Failed transaction:
`0x1f55a77db54e15fadab7fbe21b7f785097bac06f3963578cc8e2b65fdc24a94c`.

Its receipt reached `ACCEPTED` with the contract rollback payload. The CLI trace request was also attempted, but Studionet returned `Method not found: gen_dbg_traceTransaction`; the receipt contained the complete rollback reason. Retrying with plain string arguments succeeded.

The safe resolve receipt recorded one validator disagreement while consensus accepted the transaction; the resulting capsule was `SAFE` and consumable. The hostile resolve receipt recorded two validator disagreements while consensus accepted the transaction; the resulting capsule was `QUARANTINED` and not consumable.
