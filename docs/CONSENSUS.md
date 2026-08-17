# Consensus design

Ingress uses GenLayer consensus as a security boundary, not as decoration around an LLM call.

## What is non-deterministic

Only operations that ordinary deterministic contract code cannot reproduce enter the non-deterministic path:

1. rendering the live web source;
2. semantically classifying whether the source attempts to control an AI/agent reader;
3. judging whether a proposed excerpt is passive evidence relevant to the declared purpose.

Everything else is deterministic: URL admission, the literal tripwire, field bounds, final status derivation, terminal-state enforcement, storage, events, and `is_consumable`.

## Leader proposal

The leader returns a bounded object:

```json
{
  "reachable": true,
  "risk_mask": 0,
  "reason": "brief bounded rationale",
  "excerpts": ["verbatim source evidence"]
}
```

The leader never returns a settlement status. Contract code derives `SAFE`, `SUSPICIOUS`, or `QUARANTINED` from risk findings.

The classifier receives the caller purpose and hostile page as JSON-encoded data values and is asked for structured JSON output.

## Why `run_nondet_unsafe`

Ingress uses:

```python
gl.vm.run_nondet_unsafe(leader_fn, validator_fn)
```

because the output is a semantic classification plus source-grounded evidence. Exact prose equality would be brittle, while checking only response shape would be unsafe.

The custom validator therefore re-executes the load-bearing work independently and explicitly defines what must be equivalent.

## Validator algorithm

For each leader proposal, a validator:

1. requires a `gl.vm.Return` result with dictionary calldata;
2. independently renders the admitted URL;
3. independently classifies that source snapshot;
4. requires leader and validator reachability fields to be actual booleans;
5. requires leader and validator risk masks to be bounded integers with no unknown bits;
6. rejects reachability disagreement;
7. compares the security-relevant risk dimensions;
8. derives and compares the terminal security class;
9. uses the **same independently rendered validator snapshot** to ground leader excerpts;
10. requires each excerpt to be a bounded canonical string present in that snapshot;
11. independently judges every released excerpt as passive and relevant.

Only then does the validator return `True`.

## Equivalence rule

Exact semantic risk-category bits are useful diagnostics, but they are not the consensus settlement surface.

Two honest models can identify the same hard attack differently. For example, one may label text as `TASK_REDIRECTION` while another labels it `PROMPT_OVERRIDE`. Requiring exact category equality would reduce convergence without changing the safe outcome: both indicate semantic machine-control risk and both must quarantine the source.

Validators therefore require agreement on:

- **reachability**;
- **semantic hard-risk presence**: any of bits `1..128` versus none;
- **deterministic literal-floor presence**: bit `256`;
- **analysis-failure presence**: bit `512`;
- **derived terminal security class**;
- **source anchoring and passive/relevance of every released excerpt**.

This means a `SAFE` leader cannot be accepted by a validator that independently detects a semantic attack, literal floor, or unsafe parse failure.

## Why exact category bits are diagnostic

The stored `risk_mask` preserves the accepted leader's diagnostic taxonomy for inspection and debugging. Downstream automatic logic should not branch on one exact semantic category bit.

The stable integration API is:

```python
ingress.is_consumable(capsule_id)
```

or equivalently the derived `status` plus evidence count.

## Same-snapshot evidence verification

The validator does **not** classify one page fetch and then fetch again to ground excerpts.

Its independent `inspect_once(include_source=True)` returns both classification findings and the exact bounded source snapshot used for that classification. Evidence anchoring then uses that same snapshot.

This removes an avoidable time-of-check/time-of-use window on fast-changing pages and saves one redundant web render per validator.

## Forged leader resistance

A custom validator must assume the leader payload itself can be malicious.

Ingress therefore rejects, before semantic comparison:

- non-boolean reachability values such as the string `"true"`;
- boolean values used as integer masks;
- negative masks;
- masks containing unknown bits;
- non-list excerpt fields;
- non-string excerpts;
- oversized or non-canonical excerpts;
- excerpts absent from the validator's source snapshot.

This is tested with `direct_vm.run_validator(leader_result=...)`, which supplies deliberately forged leader payloads directly to the captured validator.

## Deterministic status derivation

The model does not decide the state transition.

```text
semantic hard risk present   -> QUARANTINED
analysis parse failure       -> QUARANTINED
literal floor only           -> SUSPICIOUS
no risk dimension            -> SAFE
source unavailable           -> UNAVAILABLE
```

A `SAFE` capsule with no grounded excerpt is still not consumable.

## Why the deterministic lexical floor exists

LLMs are probabilistic. A source containing an unmistakable literal phrase such as `ignore previous instructions` should not become `SAFE` merely because a model misses it.

The lexical floor is intentionally small. It is not a complete injection detector. Its purpose is to guarantee a deterministic minimum for a handful of obvious control phrases while semantic consensus handles indirect, paraphrased, contextual, or obfuscated attacks.

## Consensus failure is safer than forced resolution

If leader and validators cannot agree on the security-relevant dimensions, Ingress does not force a safety result from that proposal.

That is preferable to writing a consumable capsule under unresolved disagreement.

## Direct proof in tests

The Direct Mode suite proves substantive validation in two ways.

`test_validator_reclassifies_source_and_rejects_security_class_disagreement` keeps the leader proposal well-formed but changes the validator's independent classification from safe to semantic-risk. The validator returns `False`.

`tests/direct/test_ingress_hardening.py` also injects forged leader payloads directly with `run_validator(leader_result=...)`, including unknown risk bits, non-boolean reachability, and boolean risk masks. Each must be rejected.

Those tests distinguish Ingress from a format-only validator.
