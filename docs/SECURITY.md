# Security model

Ingress is an evidence-intake firewall for Intelligent Contracts. It reduces the chance that untrusted web content is treated as instructions by a downstream model or agent.

It is not a proof that arbitrary natural-language content is harmless.

## Assets protected

Ingress protects downstream consumers from automatically ingesting source material that attempts to:

- override governing instructions;
- impersonate system/developer authority;
- redirect the task;
- request hidden prompts, credentials, keys, or private context;
- trigger tools, transactions, downloads, messages, or code execution;
- hide or obfuscate machine-directed instructions;
- chain the reader into another instruction source.

## Trust boundaries

### Caller

The caller is untrusted and supplies only:

- a bounded HTTPS URL;
- a bounded passive evidence purpose.

The caller cannot submit the evidence body itself.

### Source

The source is hostile by default. It can contain legitimate facts and adversarial instructions in the same rendered content.

### Leader

The leader is not trusted to classify correctly or even to construct honestly typed result fields. Its proposal must pass independent validator verification.

### Validators

The security assumption is GenLayer consensus itself. Ingress does not protect against a malicious validator majority that agrees on a false result.

### Downstream consumer

The preferred automatic gate is:

```python
ingress.is_consumable(capsule_id)
```

Treating `SUSPICIOUS`, `QUARANTINED`, `UNAVAILABLE`, `CANCELLED`, or empty-evidence `SAFE` capsules as trusted evidence defeats the primitive.

Consumers should not base settlement on one exact semantic risk bit; those category bits are diagnostic. The stable decision is the derived security status and consumability gate.

## Fail-closed rules

| Condition | Result |
|---|---|
| source cannot be rendered | `UNAVAILABLE` |
| classifier output cannot be parsed | `QUARANTINED` + `UNPARSABLE_ANALYSIS` |
| classifier risk type is fractional/hex-like/unsupported | `QUARANTINED` + `UNPARSABLE_ANALYSIS` |
| semantic machine-control risk found | `QUARANTINED` |
| deterministic literal floor only | `SUSPICIOUS` |
| capsule is not SAFE | no excerpts released at all |
| no grounded excerpt | not consumable |
| validator security dimensions disagree | validator rejects proposal |
| forged leader field has wrong type/unknown bits | validator rejects proposal |
| excerpt is absent from validator snapshot | validator rejects proposal |
| excerpt is active or irrelevant | validator rejects proposal |
| excerpt attached to a non-SAFE observation | validator rejects proposal |
| leader withheld evidence the validator found releasable | validator rejects proposal |

## URL admission and SSRF defence in depth

Before consensus, Ingress accepts only a deliberately conservative public HTTPS hostname shape.

It rejects:

- non-HTTPS URLs;
- credentials in the authority;
- explicit ports;
- localhost and `.localhost`;
- `.local` and `.internal` names;
- ordinary IPv4 loopback/private/link-local forms;
- numeric-only legacy IP spellings such as shortened or integer forms;
- leading-zero, percent-encoded, backslash, or other ambiguous host syntax;
- malformed DNS labels;
- DNS-wrapper hostnames beginning with a private IPv4 prefix.

This is defence in depth, not a complete DNS/network SSRF solution. Contract code cannot observe every resolver, proxy, routing, rebinding, or validator-infrastructure behaviour.

Validator/network operators still need appropriate egress controls.

## Prompt isolation

Attacker-controlled natural language is framed as data rather than inserted as a free-form instruction section.

The classifier receives:

- `CALLER_PURPOSE_JSON`;
- `UNTRUSTED_SOURCE_JSON`.

The excerpt validator similarly receives JSON-framed purpose and candidate excerpt values.

This makes newlines, quotes, and fake section-marker text part of encoded data rather than allowing them to create a new top-level prompt section.

Prompt wording alone is not treated as a sufficient defence. It is combined with independent classification, deterministic lexical checks, strict result parsing, source grounding, and validator rejection on security disagreement.

## Model-output hardening

The semantic classifier is asked for structured JSON.

`risk_mask` accepts only:

- a Python integer; or
- a decimal-digit string representing an integer.

It rejects booleans, floats, hex-like strings, negative values, and unsupported semantic bits. Invalid classifier output becomes `UNPARSABLE_ANALYSIS`, which is quarantined.

The custom validator separately validates leader fields because the leader proposal itself is untrusted. A forged unknown bit cannot be silently masked away into a safe result.

## Evidence anchoring

The leader may propose at most a small bounded set of short excerpts.

Leader-side canonicalisation keeps only string excerpts that occur in the leader's rendered source, and drops evidence entirely when the leader's own classification is not SAFE.

Every validator then independently renders and classifies its own source snapshot. The **same snapshot** is used to verify that each leader excerpt:

- is a string;
- is within the size bound;
- is already canonical rather than changing meaning through validator normalisation;
- occurs in the validator-observed source;
- passes a separate passive/relevance judgment.

Using one validator snapshot for classification and anchoring avoids a second-fetch time-of-check/time-of-use window.

## Evidence suppression

Anchoring alone only constrains what a leader releases. It says nothing about what a leader silently withholds.

Because `is_consumable` is `SAFE` plus a non-empty excerpt list, an unchecked empty list would let a leader decide consumability by itself: the same SAFE page could settle as usable evidence or as an inert capsule depending only on which leader proposed it, with no validator ever examining that choice.

Validators therefore bind availability to their own observation. When a leader releases nothing, each validator runs its own grounded candidates through the **same** release judgment used to gate released excerpts, and rejects the proposal if any candidate would have passed.

Because both directions share one acceptance test, the rule is symmetric: a capsule is non-consumable only when validators independently observed nothing releasable. A candidate the judge refuses is not available evidence, so an honest leader is never penalised for declining to release something unreleasable.

Two limitations are worth stating plainly. This binds *availability*, not *selection*: among several releasable excerpts, which subset a leader picks is still its own choice, and every pick is independently grounded and judged. And on genuinely borderline pages honest models can disagree about availability, in which case the proposal is rejected and the capsule stays `PENDING` rather than settling unverified.

## Consensus equivalence and semantic labels

Validators are not required to choose the identical fine-grained semantic category for the same hard attack. Two honest models may label the same text differently while agreeing it is unsafe.

They must agree on:

- reachability;
- whether any semantic hard risk exists;
- deterministic literal-floor presence;
- analysis-failure presence;
- terminal security class;
- whether releasable evidence existed at all.

A leader cannot therefore propose a consumable `SAFE` result when a validator independently observes any hard-risk dimension, and cannot propose a non-consumable `SAFE` result when a validator independently observes releasable evidence.

## What SAFE means

`SAFE` means only:

> The accepted consensus path did not identify source-directed machine-control risk under Ingress's defined observation and taxonomy.

`SAFE` does **not** mean:

- the source is truthful;
- the source is authoritative;
- the source is independent;
- the source is fresh;
- the evidence is sufficient to settle a market, escrow, insurance policy, or governance action;
- the page is safe for an ordinary browser;
- the domain owner is trustworthy.

Those are separate primitives and policies.

## Known limitations

### Semantic false negatives

A validator majority can independently miss a novel or subtle attack. Consensus reduces single-model error and unilateral manipulation; it does not make natural-language security classification infallible.

### Semantic false positives

Security research, documentation, and news can quote attack language legitimately. The semantic classifier is instructed to reason about context, but the deterministic literal floor can still produce `SUSPICIOUS` on quoted control phrases.

That middle state is intentionally fail closed; it is not an accusation against the publisher.

### Rendered-text boundary

Ingress classifies GenLayer's rendered text view. Content absent from that representation is outside the current observation boundary, including some image, binary, script-only, or non-rendered channels.

Future versions should add new observation channels explicitly rather than silently widening the current guarantee.

### DNS/network visibility

The deterministic hostname parser can reject many dangerous and ambiguous forms, but it cannot prove how every hostname will resolve at execution time. Network-layer protections remain complementary.

### Purpose interpretation

Purpose is bounded, screened for obvious control language, and JSON-framed, but it remains natural language. Integrators should prefer stable application-defined purpose templates over arbitrary end-user prompts.

### Diagnostic mask stability

Fine-grained semantic category bits are not guaranteed to be identical across honest validators. Downstream settlement should use `status`/`is_consumable`, not a particular category bit.

## No privileged bypass

There is no owner/admin method that can:

- mark quarantined evidence safe;
- edit a terminal capsule;
- replace evidence;
- disable validator verification;
- change the risk dictionary;
- bypass `is_consumable`.

## Integration rule

The safest default integration is:

```text
if not ingress.is_consumable(capsule_id):
    do not pass capsule excerpts into downstream nondeterministic reasoning
```

Then apply truth corroboration, freshness, authority, policy, and settlement logic after the Ingress gate.
