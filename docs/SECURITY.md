# Security model

Ingress is an evidence-intake firewall for Intelligent Contracts. It reduces the chance that untrusted web content is treated as instructions by a downstream model or agent.

It is not a proof that arbitrary natural-language content is harmless.

## Assets protected

Ingress protects downstream contracts and agents from automatically consuming web evidence that attempts to:

- override governing instructions;
- impersonate system/developer authority;
- redirect the task;
- request hidden prompts, credentials, keys, or private context;
- trigger tools, transactions, downloads, messages, or code execution;
- hide or obfuscate machine-directed instructions;
- chain the reader into another instruction source.

## Trust boundaries

### Caller

The caller is untrusted.

The caller can provide only:

- a public HTTPS URL;
- a bounded passive evidence purpose.

The caller cannot submit the evidence body itself.

### Source

The source is hostile by default. It may contain both legitimate evidence and adversarial instructions.

### Leader

The leader is not trusted to classify correctly. Its result must pass independent validator verification.

### Validators

The security assumption is GenLayer consensus itself. Ingress does not protect against a malicious validator majority that agrees on a false classification.

### Downstream consumer

Downstream contracts must use `is_consumable(capsule_id)` or enforce the equivalent rule. Treating `SUSPICIOUS`, `QUARANTINED`, `UNAVAILABLE`, or empty-evidence `SAFE` capsules as trusted content defeats the primitive.

## Fail-closed rules

Ingress fails closed in the following cases:

| Condition | Result |
|---|---|
| web source cannot be read | `UNAVAILABLE` |
| classifier output cannot be parsed | `QUARANTINED` + `UNPARSABLE_ANALYSIS` |
| classifier emits unsupported bits | `QUARANTINED` + `UNPARSABLE_ANALYSIS` |
| semantic machine-control risk found | `QUARANTINED` |
| only deterministic literal tripwire fires | `SUSPICIOUS` |
| no grounded excerpt exists | not consumable |
| validator security class differs | validator rejects proposal |
| validator cannot independently anchor excerpt | validator rejects proposal |
| validator judges excerpt active/unrelated | validator rejects proposal |

## URL admission and SSRF

Ingress rejects obvious dangerous URL forms before consensus:

- non-HTTPS URLs;
- credentials embedded in URL authority;
- explicit ports;
- localhost and `.localhost`;
- `.local` and `.internal` names;
- obvious IPv4 loopback, private, and link-local ranges.

This is defence in depth, not a complete DNS/network SSRF solution. DNS rebinding, unusual address encodings, future network features, proxy behaviour, and infrastructure-level routing rules remain outside the contract's deterministic visibility.

Network operators should still enforce egress protections appropriate for validator infrastructure.

## Prompt isolation

The classifier prompt explicitly marks source text as hostile data and forbids obeying, continuing, simulating, browsing from, or executing instructions from the source.

That prompt is not considered sufficient security by itself. It is combined with:

- an independent validator classification;
- a deterministic lexical floor;
- source-anchored evidence;
- a second independent excerpt safety/relevance judgment;
- fail-closed status derivation.

## Evidence anchoring

The leader may propose only short evidence excerpts.

Each excerpt is normalised and accepted only if it occurs in the rendered source. Validators then independently render the source and repeat the anchoring check.

This prevents a leader from replacing hostile source text with a convenient safe paraphrase and presenting that paraphrase as evidence from the page.

## What SAFE means

`SAFE` means only:

> The consensus path did not find evidence that this source is attempting to control the model/agent reading it, under the defined risk taxonomy.

`SAFE` does **not** mean:

- the source is truthful;
- the source is authoritative;
- the source is independent;
- the source is fresh;
- the evidence satisfies a market, escrow, insurance, or governance condition;
- the page is free of malware for a normal browser;
- the domain owner is trustworthy.

Those are separate questions and should be handled by separate primitives.

## Known limitations

### Semantic false negatives

Two or more validators may independently miss a novel or subtle attack. Consensus reduces single-model error and manipulation; it does not make language-model classification infallible.

### Semantic false positives

Security research pages, documentation, and news articles can legitimately quote attack phrases. The LLM classifier is instructed to distinguish descriptive quotation from instructions directed at the reader. The deterministic lexical floor is intentionally conservative and may still mark such a page `SUSPICIOUS`.

This is deliberate: `SUSPICIOUS` is a fail-closed middle state, not an accusation that the publisher is malicious.

### Rendered-text boundary

The current primitive classifies GenLayer's rendered text view. Content that is completely absent from that representation is outside the classifier's observation. This repository therefore does not claim perfect detection of CSS-hidden, script-generated, binary, image-based, or other non-rendered instruction channels.

A future version can add raw-HTML and image passes as separate independently validated evidence channels rather than silently expanding the current guarantee.

### Purpose interpretation

Purpose is bounded and screened for obvious control language, but it is still natural language. Integrators should use stable, application-defined purpose templates rather than passing arbitrary end-user prompts when possible.

## No privileged bypass

There is no owner/admin method that can:

- mark a quarantined capsule safe;
- edit a terminal capsule;
- replace evidence;
- disable the validator;
- change the risk dictionary;
- bypass `is_consumable`.

This is intentional for a reusable security primitive.

## Integration rule

The safest default integration is:

```text
if not ingress.is_consumable(capsule_id):
    do not pass capsule excerpts into downstream nondeterministic reasoning
```

Then apply any additional corroboration, freshness, policy, or settlement checks after the Ingress gate.
