# Ingress submission notes

## Category

Standalone GenLayer Intelligent Contract.

Ingress is deliberately **not** a Project submission. There is no frontend, dashboard, wallet UX, backend product flow, indexer, or application-specific settlement experience.

## One-sentence purpose

Ingress is a reusable consensus firewall that screens untrusted live web content for machine-directed prompt/action attacks and releases only bounded, validator-verified, source-anchored passive evidence for other contracts to consume.

## Repository and live evidence

- Repository: `https://github.com/ometere123/ingress`
- Studionet contract: `0x86506D4017B5B47Ce8Cd03b3C561E3bd96cfA0e5`
- Deployment transaction: `0x277e11d40d3247b423017b12d47be884ccf5630a4bd6eb45942a184969f1dc72`
- Deployment state: `FINALIZED`, `MAJORITY_AGREE`
- Deployment source commit: `594d32439eb67af666bc69935ff161ababc58741`
- Deployment method: official genlayer-test Studio Mode
- Full deployment/smoke evidence: `docs/DEPLOYMENT.md`

`contracts/ingress.py` has not changed since the deployment source commit. Subsequent commits affect only tests, tooling dependencies, fixtures and documentation; the deployable contract source remains identical.

## What changed after the first review

The first submission was rejected on one specific consensus-soundness defect, quoted here in full:

> The validator independently re-fetches and reclassifies the page, but it accepts an empty excerpt list even when a grounded relevant excerpt could be released. That lets the same SAFE inspection become consumable or non-consumable based on an unverified leader choice. Require validators to bind excerpt availability, or derive consumability from their own observation, before resubmitting.

The finding was correct. `is_consumable` is `status == SAFE and len(excerpts) > 0`, and the previous validator verified only the excerpts a leader chose to release. An empty list was accepted unconditionally, so the emptiness of that list was the one consensus-visible field no validator ever examined. Two honest leaders observing the identical SAFE page could produce two different capsules, and a leader could suppress evidence it disliked while still returning a perfectly well-formed SAFE proposal.

This resubmission implements both halves of the requested remedy with one symmetric rule, applied through a single shared acceptance test `judge_excerpt_release(excerpt, purpose)`:

| Leader proposed | Validator requirement |
|---|---|
| one or more excerpts | every excerpt is grounded in the validator's own snapshot **and** passes the validator's own release judgment |
| nothing | **no** grounded candidate in the validator's own snapshot passes that same release judgment |

Because both directions share one acceptance test, the resulting invariant is total:

> A capsule is non-consumable only when validators independently observed nothing releasable.

Consumability is therefore derived from validator observation, not from leader discretion. The withheld-evidence check deliberately reuses the strict release judgment rather than a looser "was anything relevant here" probe: a candidate the judge would refuse to release is not available evidence, so an honest leader is never penalised for declining to release something unreleasable.

A second consistency change was required to make that rule safe for honest leaders. `excerpts_for_class` is now shared by the leader observation path, the validator, and settlement:

```python
if risk_class(mask) != STATUS_SAFE:
    return []
```

Evidence rides on `SAFE` only. An honest observer never proposes excerpts extracted from a source its own classification already condemned, and a leader that attaches excerpts to a risky observation is now rejected outright rather than having them quietly dropped at settlement.

Verification of the fix:

- `contracts/ingress.py` — new `judge_excerpt_release` and `excerpts_for_class` helpers; rewritten excerpt section in `validator_fn`; class-bound evidence in `inspect_once` and `resolve`.
- `tests/direct/test_ingress_hardening.py` — 7 new Direct Mode tests. The headline regression is `test_validator_rejects_leader_that_withholds_available_evidence`, which submits a well-formed SAFE leader proposal with an empty excerpt list while the validator's own snapshot holds a grounded, releasable excerpt, and asserts the validator returns `False`.
- Over-rejection guards: `test_validator_accepts_empty_evidence_when_it_observes_none` and `test_validator_accepts_empty_evidence_when_candidate_fails_release_test` confirm the binding does not reject honest empty results.
- `scripts/preflight.py` — 12 new checks, including AST assertions that `validator_fn` consults its own excerpt observation, applies `judge_excerpt_release` in both directions, and branches on an empty leader list.
- The four new negative regressions were confirmed to fail against the pre-fix contract and pass against the fixed one; the two over-rejection guards pass against both.

Honest limitations, stated in [`docs/SECURITY.md`](docs/SECURITY.md): this binds evidence *availability*, not *selection* — among several releasable excerpts, which subset a leader picks is still its own choice, and every pick is independently grounded and judged. On genuinely borderline pages honest models can disagree about availability, in which case the proposal is rejected and the capsule stays `PENDING` rather than settling unverified.

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
6. every excerpt receives an independent passive/relevance judgment;
7. validators also bind *whether any evidence was releasable at all*, so an empty excerpt list is never an unverified leader choice.

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
- capsule is not `SAFE` -> no excerpts released at all;
- no grounded evidence -> not consumable;
- validator disagreement -> proposal rejected;
- forged leader type/unknown bit -> proposal rejected;
- leader withheld evidence the validator found releasable -> proposal rejected;
- terminal capsule -> cannot resolve again;
- no administrator -> no safety override.

## Validation evidence

| Gate | Result |
|---|---|
| SDK-free preflight | **PASS, 86/86** |
| Python source compilation | **PASS** |
| Direct Mode | **PASS, 26 passed / 0 failed / 0 skipped** |
| Pickling | **PASS**, `check_pickling=True` |
| Studionet integration | **PASS, 4 passed / 0 failed / 0 skipped** |
| GenLayer CLI | **PASS**, `0.39.2` |
| Studionet deployment | **PASS**, finalized |
| Safe live source | **PASS**, resolve `0x47703a64c766f1955452b8863cd0988982e04008c310df939737e8459ee095ea`, `SAFE`, risk `0`, grounded excerpt, consumable `true` |
| Hostile live fixture | **PASS**, resolve `0x1b0c6f3d6f4cf6d5385f5407d622a5c16d2b9dda5fffeef9fbb762ea4d9d450a`, `QUARANTINED`, risk `265`, consumable `false` |
| GenVM linter | **PASS**, published `genvm-linter==0.11.0`, `check --json` exit `0` |

The Direct Mode Windows harness required an external, uncommitted temporary-file cleanup shim. No contract change was required to obtain the 26/26 result.

The primary GenVM linter gate is green; its only output warning was informational `I200` about a newer runner.

The committed Studionet integration suite independently redeploys Ingress through official Studio Mode and verifies the public read surface, SAFE consumable evidence, hostile non-consumable evidence and cancellation. Each behavioural test uses a fresh disposable deployment so it can be run independently without relying on pytest ordering.

## Live runtime proof reviewers should notice

The safe Studionet resolution transaction:

`0x47703a64c766f1955452b8863cd0988982e04008c310df939737e8459ee095ea`

resolved capsule `1` to `SAFE`, risk mask `0`, with a grounded excerpt. `is_consumable(1)` returned `true`.

The hostile Studionet resolution transaction:

`0x1b0c6f3d6f4cf6d5385f5407d622a5c16d2b9dda5fffeef9fbb762ea4d9d450a`

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
pytest tests/integration/ -v -s --network studionet
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
4. `tests/integration/test_ingress_studionet.py`
5. `docs/CONSENSUS.md`
6. `docs/DEPLOYMENT.md`
7. `docs/SECURITY.md`
8. `scripts/preflight.py`
9. `docs/INTEGRATION.md`

## Scope honesty

Ingress does not claim that `SAFE` means a page is true, reputable, independent, fresh, or sufficient to settle money.

It also does not claim perfect prompt-injection detection, complete DNS-rebinding/network-level SSRF prevention, or protection against a malicious validator majority.

It answers one reusable evidence-intake question. Truth corroboration, semantic drift, policy evaluation, settlement, and application UX remain separate layers.
