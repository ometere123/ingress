# Ingress submission notes

## Category

Standalone GenLayer Intelligent Contract.

Ingress is deliberately **not** a Project submission. There is no frontend, dashboard, wallet UX, backend product flow, indexer, or application-specific settlement experience.

## One-sentence purpose

Ingress is a reusable consensus firewall that screens untrusted live web content for machine-directed prompt/action attacks and releases only bounded, validator-verified, source-anchored passive evidence for other contracts to consume.

## Repository and live evidence

- Repository: `https://github.com/ometere123/ingress`
- Studionet contract: `0xd7fe4E83829E357CB192071F05Fa5416A1ae485F`
- Deployment transaction: `0xa9091bd32f5f3b5d5de3c17ce1b04c3545cd1d46df79dbdfbf02acd48bc2605b`
- Deployment state: `FINALIZED`, `MAJORITY_AGREE`
- Deployment source commit: `75a965eaa8760c26fe86fa8918c690ca150702ae`
- Full deployment/smoke evidence: `docs/DEPLOYMENT.md`

`contracts/ingress.py` has not changed since the deployment source commit. Later commits add the public hostile fixture and reviewer/deployment documentation only.

## The problem

An Intelligent Contract may need live web evidence, but the page carrying a useful fact can also contain text that attempts to control the model reading it: ignore governing instructions, impersonate higher authority, reveal secrets, call tools, transact, download something, or follow another instruction chain.

Passing arbitrary internet text directly into downstream reasoning makes every consumer responsible for rebuilding this security boundary independently.

Ingress isolates that boundary into a reusable contract primitive.

## What the primitive does

A caller opens an inspection with a public HTTPS URL and a bounded passive evidence purpose.

Resolution produces one terminal evidence-security capsule:

```text
PENDING -> SAFE
        -> SUSPICIOUS
        -> QUARANTINED
        -> UNAVAILABLE
        -> CANCELLED
```

Only `SAFE` plus at least one independently grounded excerpt is consumable. Downstream contracts can use `is_consumable(capsule_id)` as the stable intake gate.

Ingress does not decide whether a fact is true, authoritative, fresh, independent, or sufficient to settle anything.

## Why consensus is load-bearing

Without GenLayer consensus, one API operator or one model invocation becomes the sole authority deciding whether hostile internet content is safe to feed into downstream reasoning.

With Ingress:

1. the leader independently renders and classifies the live source;
2. validators independently render and classify it again;
3. validators reject malformed/forged leader fields and unknown risk bits;
4. validators require agreement on reachability, semantic hard-risk presence, literal-floor presence, parser-failure presence, and terminal security class;
5. every released excerpt must be anchored to the validator's own source snapshot;
6. every excerpt receives an independent passive/relevance judgment.

Fine-grained semantic category bits are diagnostic. The stable downstream surface is the derived status and `is_consumable` gate.

## Why this is not a thin LLM wrapper

| Rejected pattern | Ingress |
|---|---|
| Generic “AI decides X” | the LLM reports observations; deterministic code derives the terminal state |
| Format-only validator | validators independently re-fetch/re-classify and reject substantive security disagreement |
| Caller-submitted evidence | source content is fetched inside the consensus path from the stored URL |
| Generic web oracle | Ingress judges evidence-intake safety, not truth |
| Full application | exactly one deployable contract, no frontend/product flow |

A syntactically valid SAFE-looking leader result can still be rejected when the validator independently detects hard risk. That behavior is exercised in Direct Mode.

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
- forged leader type/unknown bit -> proposal rejected;
- terminal capsule -> cannot resolve again;
- no administrator -> no safety override.

## Validation evidence

| Gate | Result |
|---|---|
| SDK-free preflight | **PASS, 74/74** |
| Python source compilation | **PASS** |
| Direct Mode | **PASS, 19 passed / 0 failed / 0 skipped** |
| Pickling | **PASS**, `check_pickling=True` |
| GenLayer CLI | **PASS**, `0.39.2` |
| Studionet deployment | **PASS**, finalized |
| Safe live source | **PASS**, `SAFE`, risk `0`, two grounded excerpts, consumable `true` |
| Hostile live fixture | **PASS**, `QUARANTINED`, risk `265`, consumable `false` |
| GenVM linter | **environment/tooling blocked**; no pass is claimed |

The Direct Mode Windows harness required an external, uncommitted temporary-file cleanup shim. No contract change was required to obtain the 19/19 result.

The optional linter row is the only tooling row not green and is not a contract, consensus, Direct Mode, pickling, deployment, or live-runtime failure.

## Live runtime proof reviewers should notice

The safe Studionet resolution transaction:

`0xd72c3bd2817b62ce6c6231b1e5d88d081a63187e96a459f92169ff88c14bbc03`

resolved capsule `1` to `SAFE`, risk mask `0`, with two grounded excerpts. `is_consumable(1)` returned `true`.

The hostile Studionet resolution transaction:

`0xa2b2c6fb4c858016098b94f190e3c87e5b4d1274ad8ff49eb459bd43a2f76d51`

resolved capsule `3` to `QUARANTINED`, risk mask `265` (`PROMPT_OVERRIDE`, `SECRET_EXFILTRATION`, `LITERAL_CONTROL_PHRASE`). `is_consumable(3)` returned `false`.

The hostile input is the public repository fixture `fixtures/hostile_evidence.txt`.

## Why it is reusable

Ingress has no knowledge of the downstream settlement or application. The same deployed interface can sit in front of prediction markets, insurance triggers, escrows, governance, policy evaluators, autonomous agents, corroboration contracts, and monitoring systems.

Its output is a typed evidence-security capsule, not a user-facing recommendation.

A downstream primitive can compose it as:

```text
untrusted source
      |
      v
   Ingress
      |
SAFE + grounded excerpt
      |
      v
truth / corroboration / policy / settlement
```

## Testing/deployment commands

```bash
python scripts/preflight.py
pip install -r requirements-test.txt
pytest tests/direct/ -v -s
```

For a configured/unlocked GenLayer CLI account:

```bash
python scripts/deploy_studionet.py
```

The deploy helper does not accept a private key and does not invoke `genvm-lint`.

## What reviewers should inspect first

1. `contracts/ingress.py`
2. `tests/direct/test_ingress_hardening.py`
3. `tests/direct/test_ingress.py`
4. `docs/CONSENSUS.md`
5. `docs/DEPLOYMENT.md`
6. `docs/SECURITY.md`
7. `scripts/preflight.py`
8. `docs/INTEGRATION.md`

## Scope honesty

Ingress does not claim that `SAFE` means a page is true, reputable, independent, fresh, or sufficient to settle money.

It also does not claim perfect prompt-injection detection, complete DNS-rebinding/network-level SSRF prevention, or protection against a malicious validator majority.

It answers one reusable evidence-intake question. Truth corroboration, semantic drift, policy evaluation, settlement, and application UX remain separate layers.
