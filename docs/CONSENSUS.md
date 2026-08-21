# Consensus design

Ingress uses GenLayer consensus as a security boundary, not as decoration around an LLM call.

## What is non-deterministic

Only operations that ordinary deterministic contract code cannot reproduce enter the non-deterministic path:

1. rendering the live web source;
2. semantically classifying whether the source attempts to control an AI/agent reader;
3. judging whether an excerpt is passive evidence relevant to the declared purpose — applied both to excerpts a leader released and to grounded candidates a leader withheld.

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
10. requires a non-SAFE derivation to carry no excerpts at all;
11. requires each released excerpt to be a bounded canonical string present in that snapshot;
12. independently judges every released excerpt as passive and relevant;
13. when the leader released nothing, independently judges its **own** grounded candidates and rejects the proposal if any of them was releasable.

Only then does the validator return `True`.

## Excerpt availability is validator-bound

Consumability is `status == SAFE and len(excerpts) > 0`. If a validator verified only the excerpts a leader chose to release, then the empty list would be the one consensus-visible field no validator ever checked.

That would be a real soundness gap rather than a cosmetic one. Two honest leaders observing the identical SAFE page could produce two different capsules — one consumable, one not — purely from an unverified choice to stay silent. A leader could also suppress evidence it disliked while still returning a perfectly well-formed, perfectly SAFE proposal.

Ingress therefore binds excerpt availability to validator observation in both directions, using one acceptance test for both:

```python
judge_excerpt_release(excerpt, purpose) -> bool
```

| Leader proposed | Validator requirement |
|---|---|
| one or more excerpts | every excerpt is grounded in the validator's own snapshot and passes the validator's own release judgment |
| nothing | no grounded candidate in the validator's own snapshot passes that same release judgment |

The withheld-evidence check reuses the release judgment rather than asking a looser "was anything relevant here" question. A marginal or irrelevant candidate the judge would refuse to release is not treated as available evidence, so honest leaders are not punished for declining to release something that could never have been released anyway.

The resulting rule is symmetric and total:

> A capsule is non-consumable only when validators independently observed nothing releasable.

## Evidence rides on SAFE only

`excerpts_for_class` is shared by the leader observation path, the validator, and settlement:

```python
if risk_class(mask) != STATUS_SAFE:
    return []
```

An honest observer never proposes evidence extracted from a source its own classification already condemned, so a non-SAFE proposal carries no excerpts. A leader that attaches excerpts to a risky observation is rejected outright rather than having them quietly dropped at settlement.

This makes the excerpt field total: a capsule carries evidence if and only if its derived class is SAFE and validators agreed that evidence was available.

## Equivalence rule

Exact semantic risk-category bits are useful diagnostics, but they are not the consensus settlement surface.

Two honest models can identify the same hard attack differently. For example, one may label text as `TASK_REDIRECTION` while another labels it `PROMPT_OVERRIDE`. Requiring exact category equality would reduce convergence without changing the safe outcome: both indicate semantic machine-control risk and both must quarantine the source.

Validators therefore require agreement on:

- **reachability**;
- **semantic hard-risk presence**: any of bits `1..128` versus none;
- **deterministic literal-floor presence**: bit `256`;
- **analysis-failure presence**: bit `512`;
- **derived terminal security class**;
- **source anchoring and passive/relevance of every released excerpt**;
- **whether releasable evidence existed at all**.

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
- excerpts absent from the validator's source snapshot;
- excerpts attached to a non-SAFE derivation;
- an empty excerpt list when the validator's own snapshot held releasable evidence.

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

A `SAFE` capsule with no grounded excerpt is still not consumable — but it can only reach that state when validators independently agreed there was nothing releasable to ground.

## Why the deterministic lexical floor exists

LLMs are probabilistic. A source containing an unmistakable literal phrase such as `ignore previous instructions` should not become `SAFE` merely because a model misses it.

The lexical floor is intentionally small. It is not a complete injection detector. Its purpose is to guarantee a deterministic minimum for a handful of obvious control phrases while semantic consensus handles indirect, paraphrased, contextual, or obfuscated attacks.

## Consensus failure is safer than forced resolution

If leader and validators cannot agree on the security-relevant dimensions, Ingress does not force a safety result from that proposal.

That is preferable to writing a consumable capsule under unresolved disagreement.

The availability binding widens what counts as disagreement: a leader that withholds releasable evidence is rejected and the transaction rotates to another leader. On a genuinely borderline page two honest models can disagree about whether anything was releasable, and the proposal is then rejected rather than settled. Rotation exhaustion leaving the capsule `PENDING` for a later `resolve` call is the intended outcome; a capsule whose consumability nobody verified is not.

## Direct proof in tests

The Direct Mode suite proves substantive validation in three ways.

`test_validator_reclassifies_source_and_rejects_security_class_disagreement` keeps the leader proposal well-formed but changes the validator's independent classification from safe to semantic-risk. The validator returns `False`.

`test_validator_rejects_leader_that_withholds_available_evidence` keeps the leader proposal well-formed **and** SAFE, with an empty excerpt list, while the validator's own snapshot contains a grounded excerpt that passes the validator's own release judgment. The validator returns `False`. Its counterparts `test_validator_accepts_empty_evidence_when_it_observes_none` and `test_validator_accepts_empty_evidence_when_candidate_fails_release_test` confirm the binding does not reject honest empty results.

`tests/direct/test_ingress_hardening.py` also injects forged leader payloads directly with `run_validator(leader_result=...)`, including unknown risk bits, non-boolean reachability, boolean risk masks, and excerpts attached to a risky observation. Each must be rejected.

Those tests distinguish Ingress from a format-only validator.
