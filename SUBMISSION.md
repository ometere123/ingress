# Ingress submission notes

## Category

Standalone GenLayer Intelligent Contract.

Ingress is deliberately **not** a Project submission. There is no frontend, dashboard, wallet UX, backend product flow, indexer, or application-specific settlement experience.

## One-sentence purpose

Ingress is a reusable consensus firewall that screens untrusted live web content for machine-directed prompt/action attacks and releases only bounded, validator-verified, source-anchored passive evidence for other contracts to consume.

## Why it is a primitive

Ingress has no knowledge of the downstream settlement or application. The same deployed interface can sit in front of prediction markets, insurance triggers, escrows, governance, policy evaluators, autonomous agents, corroboration contracts, and monitoring systems.

Its output is a typed evidence-security capsule, not a user-facing recommendation.

## Why consensus is load-bearing

Without GenLayer consensus, one operator/model becomes the sole authority deciding whether hostile internet content is safe to feed into downstream reasoning.

With Ingress:

1. the leader independently renders and classifies the live source;
2. validators independently render and classify it;
3. validators reject malformed/forged leader fields and unknown risk bits;
4. validators require agreement on reachability, semantic hard-risk presence, literal-floor presence, parser-failure presence, and terminal security class;
5. every released excerpt must be anchored to the validator's own source snapshot;
6. every excerpt receives an independent passive/relevance judgment.

Fine-grained semantic category bits are diagnostic; settlement depends on the derived class and `is_consumable` gate.

## State design

```text
PENDING -> SAFE
        -> SUSPICIOUS
        -> QUARANTINED
        -> UNAVAILABLE
        -> CANCELLED
```

Terminal capsules cannot be resolved again. Only the requester may cancel, and only while pending. Resolution is permissionless. There is no administrator or privileged safety override.

## Deterministic responsibilities

- URL/hostname admission and ambiguous-host rejection;
- purpose bounds and obvious control-channel rejection;
- deterministic literal attack floor;
- strict model risk-field parsing;
- terminal status derivation;
- single-resolution/cancellation rules;
- storage and events;
- `is_consumable` evidence gate.

## Non-deterministic responsibilities under consensus

- rendering the live source;
- semantic machine-control classification;
- passive/relevant excerpt judgment.

The model reports observations. Deterministic contract code decides what those observations are allowed to become.

## Failure policy

- unreadable source -> `UNAVAILABLE`;
- malformed/fractional/unsupported classifier result -> `QUARANTINED`;
- semantic attack -> `QUARANTINED`;
- obvious literal control phrase -> at least `SUSPICIOUS`;
- no grounded evidence -> not consumable;
- validator disagreement -> proposal rejected;
- forged leader type/unknown bit -> proposal rejected.

## Tests reviewers should notice

The Direct Mode suite goes beyond happy-path state tests.

`test_validator_reclassifies_source_and_rejects_security_class_disagreement` proves a syntactically valid leader result is rejected when the validator independently detects a hard risk.

`tests/direct/test_ingress_hardening.py` uses `direct_vm.run_validator(leader_result=...)` to inject forged leader payloads directly, including unknown risk bits, non-boolean reachability, and boolean masks.

The repository also includes `scripts/preflight.py`, a zero-dependency source/security gate that runs without `genvm-lint` or GenLayer imports.

## Testing/deployment path

```bash
python scripts/preflight.py
pip install -r requirements-test.txt
pytest tests/direct/ -v -s
```

`requirements-test.txt` intentionally excludes the linter and lets `genlayer-test v0.29.2` install its declared compatible client dependency.

For an environment with an active/unlocked GenLayer CLI account:

```bash
python scripts/deploy_studionet.py
```

The launcher does not accept a private key and does not invoke `genvm-lint`.

## Validation status of this checkout

- SDK-free preflight: **PASS, 74/74 checks**.
- Python compilation: **PASS**.
- Direct Mode: **environment blocked** after installing `genlayer-test v0.29.2`; all 19 collected tests fail in the Windows harness's fd-0 temporary-file cleanup before the contract loads. No Direct Mode pass is claimed.
- GenVM linter: **environment blocked**; the v0.11.0 source install did not expose an installed linter CLI in this runtime.
- Studionet: **not attempted** because `genlayer` CLI is unavailable. No signer, address, transaction, or deployment claim is made.

## What reviewers should inspect first

1. `contracts/ingress.py`
2. `docs/CONSENSUS.md`
3. `tests/direct/test_ingress.py`
4. `tests/direct/test_ingress_hardening.py`
5. `docs/SECURITY.md`
6. `scripts/preflight.py`
7. `docs/INTEGRATION.md`

## Scope honesty

Ingress does not claim that `SAFE` means a page is true, reputable, independent, fresh, or sufficient to settle money.

It answers one reusable evidence-intake question. Truth corroboration, semantic drift, policy evaluation, settlement, and application UX remain separate layers.
