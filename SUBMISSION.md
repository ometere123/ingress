# Ingress submission notes

## Category

Standalone GenLayer Intelligent Contract.

Ingress is deliberately **not** a Project submission. There is no frontend, dashboard, wallet UX, backend product flow, or application-specific settlement experience in this repository.

## One-sentence purpose

Ingress is a reusable consensus firewall that screens untrusted web content for machine-directed prompt/action attacks and releases only bounded, validator-verified, source-anchored passive evidence for other contracts to consume.

## Why it is a primitive

The contract has no knowledge of the downstream use case. The same deployed interface can sit in front of:

- prediction markets;
- insurance triggers;
- escrows;
- governance contracts;
- policy evaluators;
- autonomous agents;
- fact corroboration systems;
- monitoring and drift contracts.

Its output is a typed evidence-security capsule, not a user-facing recommendation.

## Why consensus is load-bearing

Delete GenLayer consensus and one operator/model becomes the sole authority deciding whether hostile internet content is safe to feed into downstream reasoning.

With Ingress:

1. a leader independently fetches and classifies the live source;
2. validators independently fetch and classify the same source;
3. security-class disagreement rejects the proposal;
4. validators independently anchor every proposed evidence excerpt to the source they observed;
5. validators independently check each excerpt is passive and relevant.

The validator is not a format checker. `tests/direct/test_ingress.py::test_validator_reclassifies_source_and_rejects_security_class_disagreement` explicitly proves this by keeping the leader result well-formed while changing the validator's independent security classification; the validator returns `False`.

## State design

Each inspection is immutable after reaching a terminal state:

```text
PENDING -> SAFE
        -> SUSPICIOUS
        -> QUARANTINED
        -> UNAVAILABLE
        -> CANCELLED
```

Only the requester may cancel and only before resolution. Anyone may resolve a pending capsule. There is no administrator and no privileged safety override.

## Deterministic versus non-deterministic responsibilities

### Deterministic

- URL admission;
- obvious local/private target rejection;
- purpose bounds and control-language rejection;
- literal attack tripwire;
- risk-bit bounds;
- final status derivation;
- single-resolution rule;
- evidence-consumption gate;
- storage and events.

### Non-deterministic under consensus

- live source fetch;
- semantic prompt/action-injection classification;
- passive/relevant evidence judgement.

The model reports findings. Ordinary contract code decides what those findings are allowed to become.

## Failure policy

Ingress never forces an answer.

- unreadable source -> `UNAVAILABLE`;
- malformed classifier output -> `QUARANTINED`;
- unsupported classifier bits -> `QUARANTINED`;
- semantic attack -> `QUARANTINED`;
- obvious literal control phrase missed by model -> at least `SUSPICIOUS`;
- no grounded evidence -> not consumable;
- validator disagreement -> proposal rejected by consensus.

## What reviewers should inspect first

1. `contracts/ingress.py`
2. `docs/CONSENSUS.md`
3. `tests/direct/test_ingress.py`
4. `docs/SECURITY.md`
5. `docs/INTEGRATION.md`

## Scope honesty

Ingress does not claim that `SAFE` means a web page is true, reputable, independent, fresh, or sufficient to settle money. It answers only the evidence-intake question defined in the README.

This narrow scope is intentional. Truth corroboration, policy evaluation, semantic drift, settlement, and application UX should remain separate composable layers.
