# Consensus design

Ingress uses GenLayer consensus as a security boundary, not as decoration around an LLM call.

## What is non-deterministic

Only operations that cannot be reproduced by ordinary deterministic contract code enter the non-deterministic path:

1. reading the live web source;
2. semantically classifying whether the source attempts to control an AI/agent reader;
3. determining whether a proposed excerpt is passive evidence relevant to the declared purpose.

Everything else is deterministic: URL admission, lexical tripwire, risk-bit bounds, final status derivation, terminal-state enforcement, storage, and the `is_consumable` gate.

## Leader result

The leader returns a bounded object:

```json
{
  "reachable": true,
  "risk_mask": 0,
  "reason": "brief bounded rationale",
  "excerpts": ["verbatim source evidence"]
}
```

The leader does not return a final `SAFE` or `QUARANTINED` status. Contract code derives status from `risk_mask`.

## Why `run_nondet_unsafe`

Ingress uses `gl.vm.run_nondet_unsafe(leader_fn, validator_fn)` because the result is a classification with source-grounded evidence, not a value that should be exact-string matched.

The validator receives `leader_result`, requires `gl.vm.Return`, then independently performs the task again.

## Validator algorithm

For each proposal a validator:

1. independently renders the same URL;
2. independently executes the security classifier;
3. compares reachability;
4. derives the leader security class and validator security class using deterministic `risk_class(...)`;
5. rejects any class disagreement;
6. enforces the deterministic lexical-risk floor;
7. independently renders the source for evidence anchoring;
8. rejects any proposed excerpt that is not present in its own observed source;
9. independently judges each excerpt as passive/relevant evidence.

Only then does it return `True`.

## Equivalence rule

The contract deliberately does not require identical reasoning prose or an identical set of semantic risk bits when those bits map to the same fail-closed security class.

The security decision is:

```text
SAFE          mask == 0
SUSPICIOUS    literal deterministic tripwire only
QUARANTINED   semantic-risk or unparseable-analysis bit present
```

This gives validators room to describe or categorise the same attack slightly differently without allowing a SAFE/unsafe disagreement through consensus.

The important equivalence properties are:

- same reachability;
- same derived security class;
- deterministic literal-risk floor preserved;
- every released excerpt independently source-anchored;
- every released excerpt independently judged passive and relevant.

## Why the model cannot directly decide settlement

The model proposes `risk_mask` and excerpts. It cannot write state.

After consensus, deterministic contract code computes:

```python
status = risk_class(mask)
```

A semantic-risk bit always produces `QUARANTINED`. A parsing failure sets `UNPARSABLE_ANALYSIS`, which also produces `QUARANTINED`. A literal tripwire cannot produce `SAFE`.

Downstream consumption is even narrower:

```python
status == SAFE and len(excerpts) > 0
```

Therefore a safe classification without any grounded evidence cannot accidentally become useful evidence.

## Why there is a deterministic lexical floor

LLMs are probabilistic. A source containing an obvious phrase such as `ignore previous instructions` should not become `SAFE` merely because one model misses the attack.

The lexical tripwire is intentionally small. It is not marketed as a complete detector. Its job is only to create a deterministic minimum floor for a handful of unmistakable control phrases.

The semantic classifier remains necessary for attacks that are indirect, paraphrased, contextual, encoded, or otherwise not reducible to substring matching.

## Consensus failure is safer than forced resolution

If validators cannot agree on the source's security class, GenLayer does not give Ingress permission to write a terminal accepted result from that proposal.

That is preferable to forcing the primitive to choose a safety label under disagreement.

## Direct proof in tests

`tests/direct/test_ingress.py` includes a validator-disagreement test:

1. the leader sees a source and proposes `SAFE`;
2. the test swaps the validator's LLM mock to return a machine-action risk;
3. `direct_vm.run_validator()` executes the captured validator;
4. validation returns `False`.

The leader JSON remains well-formed throughout. The only thing that changed is the validator's independently derived security class. This demonstrates that the validator is checking the claim itself, not the response format.
