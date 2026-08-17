<h1 align="center">Ingress</h1>

<p align="center"><b>A reusable GenLayer consensus firewall for hostile web evidence.</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/GenLayer-Intelligent%20Contract-111111" alt="GenLayer Intelligent Contract" />
  <img src="https://img.shields.io/badge/Direct%20Mode-19%2F19%20passing-111111" alt="19 of 19 Direct Mode tests passing" />
  <img src="https://img.shields.io/badge/preflight-74%2F74%20passing-111111" alt="74 of 74 preflight checks passing" />
  <img src="https://img.shields.io/badge/Studionet-FINALIZED-111111" alt="Studionet deployment finalized" />
  <img src="https://img.shields.io/badge/license-MIT-111111" alt="MIT license" />
</p>

**Ingress screens untrusted live web content before another Intelligent Contract or agent is allowed to treat that content as evidence.** It independently re-observes hostile sources under GenLayer consensus, fails closed on malformed or unsafe analysis, and releases only bounded, validator-grounded passive excerpts.

Ingress is deliberately **contract-only**. There is no frontend, dashboard, wallet flow, backend product, indexer, or application-specific settlement experience in this repository.

```text
open_inspection(url, purpose)
        |
        v
resolve(capsule_id)
        |
        +--> SAFE          source-anchored passive evidence may be consumed
        +--> SUSPICIOUS    deterministic control-language floor fired
        +--> QUARANTINED   semantic risk or unsafe/unparseable analysis
        +--> UNAVAILABLE   source could not be read
```

Only a `SAFE` capsule with at least one validator-grounded excerpt returns `is_consumable(capsule_id) == true`.

## Live Studionet deployment

| Evidence | Value |
|---|---|
| Network | Studionet |
| Contract | `0x86506D4017B5B47Ce8Cd03b3C561E3bd96cfA0e5` |
| Deployment tx | `0x277e11d40d3247b423017b12d47be884ccf5630a4bd6eb45942a184969f1dc72` |
| Deployment state | `ACCEPTED`, `MAJORITY_AGREE` |
| Deployment source | `594d324` |
| Deployment method | official genlayer-test Studio Mode |

The deployable `contracts/ingress.py` on current `main` is unchanged from the deployed source commit. Later commits add the hostile public fixture and documentation/evidence only. Full transaction evidence is in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

Live smoke verification includes a real safe source resolving to `SAFE` with two grounded excerpts and `is_consumable == true`, and a hostile public fixture resolving to `QUARANTINED` with `is_consumable == false`.

## 30-second reviewer version

Ingress solves one narrow reusable problem: **how can a downstream Intelligent Contract consume live web evidence without blindly letting the page itself instruct or redirect the model reading it?**

The caller provides a URL and a bounded passive evidence purpose. The leader fetches and classifies the live source. Validators independently fetch and classify it again, reject malformed or forged leader fields, ground every proposed excerpt in their own observed source snapshot, and independently judge whether each released excerpt is passive and relevant. Deterministic contract code then derives the terminal status.

The model never directly writes `SAFE`, `SUSPICIOUS`, or `QUARANTINED`.

## The problem

GenLayer Intelligent Contracts can read the live web and use LLMs to interpret what they read. That creates a security boundary ordinary oracle designs do not have: a page may contain a useful fact and, in the same content, contain text intended to control the model reading it.

Examples include instructions to ignore governing prompts, impersonate system authority, expose secrets, call tools, transact, download something, or follow another page for further instructions.

If every builder implements this defence independently, downstream contracts inherit inconsistent and difficult-to-review prompt-injection handling. Ingress makes evidence intake a composable primitive.

Ingress does **not** claim to sanitise the internet or prove that a factual claim is true. Its narrower question is:

> Can this web source be released forward as passive evidence without the source itself attempting to control the model or agent reading it?

Truth corroboration, freshness, authority, policy evaluation, and settlement remain separate composable layers.

## Why this needs GenLayer

A central content-safety API simply replaces one trust problem with another operator.

Ingress needs all three of these properties:

1. **Live web access** so the source is observed by the contract execution rather than accepted from caller-supplied text.
2. **Semantic reasoning** because machine-directed manipulation cannot be completely reduced to substring rules.
3. **Independent consensus** so one model invocation cannot unilaterally decide what another contract may trust.

The leader proposes an observation. Validators independently re-fetch and re-classify the source before accepting it.

### Delete GenLayer: what breaks?

| Replacement | What is lost |
|---|---|
| Central safety API | One operator becomes the authority deciding what downstream contracts may trust. |
| One off-chain LLM | The caller/operator can choose the model output and report it selectively. |
| Regex/string filter | Obvious phrases can be caught, but paraphrased, contextual and obfuscated machine-control attempts escape purely lexical rules. |
| Format-only validator | Valid JSON can still contain a forged safe verdict or invented evidence. |
| Caller-supplied page text | The caller controls the evidence being judged, so the contract no longer observes the source independently. |

The load-bearing GenLayer property is that validators independently observe and reason about the same external source, then accept only a substantively equivalent security result.

## Why this is not the rejected pattern

| Anti-pattern | Why Ingress is different |
|---|---|
| “AI decides X” | The LLM reports bounded observations and risk findings; deterministic code derives the terminal state and consumption gate. |
| Thin LLM wrapper | URL admission, lexical floors, typed parsing, custom validator logic, source grounding, terminal-state rules and fail-closed behavior surround the model call. |
| Format-only validator | Validators independently re-fetch/re-classify and can reject a perfectly well-formed leader proposal on substantive security disagreement. |
| User-submitted text judge | The caller supplies a URL; the source content is fetched inside the nondeterministic consensus path. |
| Generic web oracle | Ingress does not decide whether a fact is true. It decides whether source content may be released forward as passive evidence. |
| Full application | There is one deployable contract and no frontend/product flow. |

## Standalone contract mission fit

| Requirement | Ingress implementation |
|---|---|
| Standalone reusable contract | One deployable `contracts/ingress.py`; no application layer |
| Real GenLayer consensus | Custom `gl.vm.run_nondet_unsafe` leader/validator flow |
| Clear state design | `PENDING` to immutable terminal evidence-security capsules |
| Thoughtful validator/equivalence logic | Independent re-fetch, re-classification, typed forged-leader checks, security-dimension equivalence and excerpt verification |
| Meaningful beyond a demo | Reusable intake gate for prediction, insurance, governance, policy, agent and corroboration contracts |
| Readable source | Bounded helpers, fixed risk taxonomy and deterministic terminal derivation |
| Documentation | Consensus, security, integration and real deployment evidence docs |
| Tests | 74/74 source preflight checks, 19/19 Direct Mode tests, pickling enabled, live Studionet smoke evidence |
| Not a Project submission | No frontend, dashboard, wallet UX, backend or settlement-specific workflow |

## Contract boundary

The repository intentionally keeps exactly one deployable contract:

```text
contracts/ingress.py
```

Supporting material:

```text
tests/direct/                    Direct Mode security and state tests
scripts/preflight.py             zero-dependency source/security preflight
scripts/deploy_studionet.py      unlocked-account Studionet deployment helper
fixtures/hostile_evidence.txt    public hostile source used in live verification
requirements-test.txt            Direct Mode deps, intentionally no linter
requirements.txt                 optional full tooling, including linter
docs/CONSENSUS.md                custom validator design
docs/SECURITY.md                 threat model and limitations
docs/INTEGRATION.md              downstream composition example
docs/DEPLOYMENT.md               real Studionet deployment/smoke evidence
SUBMISSION.md                    reviewer-oriented submission copy
gltest.config.yaml               GenLayer test configuration
```

## Architecture

```text
untrusted live URL
       |
       v
 deterministic admission
       |
       v
 leader fetch + classify
       |
       v
validators independently
  fetch + classify
       |
       v
security-dimension agreement
       |
       +--> reject forged / disagreeing leader result
       |
       v
excerpt grounding + passive/relevance verification
       |
       v
 deterministic terminal status
       |
       v
typed evidence-security capsule
       |
       v
 downstream truth / policy / settlement primitive
```

## State model

Each inspection is one-way and terminal:

```text
PENDING
  |
  +-- resolve() ----------> SAFE
  |                     --> SUSPICIOUS
  |                     --> QUARANTINED
  |                     --> UNAVAILABLE
  |
  +-- requester cancel() -> CANCELLED
```

A terminal capsule cannot be re-resolved or overwritten.

Each capsule stores:

| Field | Meaning |
|---|---|
| `requester` | account that opened the inspection |
| `url` | admitted public HTTPS source |
| `purpose` | bounded passive description of evidence needed |
| `status` | derived terminal security class |
| `risk_mask` | diagnostic machine-readable risk findings |
| `reason` | bounded classification rationale |
| `excerpts` | bounded verbatim source-anchored evidence |
| timestamps | transaction-observed creation/resolution time |

There is no owner, administrator, mutable allowlist, or privileged safety override.

## Risk taxonomy

| Bit | Name | Meaning |
|---:|---|---|
| `1` | `PROMPT_OVERRIDE` | tries to replace governing instructions |
| `2` | `ROLE_IMPERSONATION` | claims system/developer/assistant authority |
| `4` | `TASK_REDIRECTION` | redirects the evidence task |
| `8` | `SECRET_EXFILTRATION` | requests hidden prompts, credentials, keys, or secrets |
| `16` | `TOOL_OR_ACTION_COMMAND` | asks the reader to execute code, call tools, transact, message, download, or otherwise act |
| `32` | `OBFUSCATED_INSTRUCTION` | disguised machine-directed instruction |
| `64` | `HIDDEN_INSTRUCTION` | non-visible machine-directed instruction represented in rendered text |
| `128` | `EXTERNAL_INSTRUCTION_CHAIN` | sends the reader elsewhere to continue instructions |
| `256` | `LITERAL_CONTROL_PHRASE` | deterministic lexical floor |
| `512` | `UNPARSABLE_ANALYSIS` | classification could not be safely parsed |

Status derivation is deterministic:

```text
semantic-risk bit present      -> QUARANTINED
UNPARSABLE_ANALYSIS present    -> QUARANTINED
only literal floor present     -> SUSPICIOUS
no risk dimensions present     -> SAFE
fetch unavailable              -> UNAVAILABLE
```

The LLM never writes the terminal state directly.

### Stable integration rule

Fine-grained semantic category bits are **diagnostic labels**, not the settlement API. Two honest validators can recognize the same malicious source while assigning different semantic subcategories.

Consensus therefore requires agreement on security-relevant dimensions:

- source reachability;
- whether any semantic hard risk is present;
- whether the deterministic literal floor is present;
- whether analysis failed to parse safely;
- the derived terminal security class.

Downstream automatic decisions should use `status` or, preferably, `is_consumable()`. Do not make payout or privileged logic depend on one exact semantic category bit.

## Consensus design

Ingress uses one custom:

```python
gl.vm.run_nondet_unsafe(leader_fn, validator_fn)
```

### Leader

The leader:

1. renders the admitted URL in text mode;
2. bounds the observed source;
3. computes the deterministic lexical floor;
4. sends JSON-framed purpose and hostile source data to the classifier;
5. requests structured JSON classification output;
6. keeps only short string excerpts that occur verbatim in the observed source;
7. proposes reachability, risk findings, reason, and excerpts.

The hostile page is encoded as data rather than interpolated as an instruction section.

### Validator

Each validator independently:

1. renders the URL itself;
2. classifies its own source snapshot;
3. requires typed `bool` reachability and bounded integer risk fields from the leader;
4. rejects unknown risk bits or malformed leader fields;
5. checks security-relevant risk dimensions and the derived class independently agree;
6. uses the **same validator snapshot** for classification and excerpt grounding, avoiding a second-fetch time-of-check/time-of-use gap;
7. requires every leader excerpt to be a canonical bounded string present in that validator snapshot;
8. independently judges every released excerpt as passive and relevant to the caller purpose.

A validator is therefore not a JSON/schema checker. The Direct Mode suite explicitly injects forged leader payloads using `direct_vm.run_validator(leader_result=...)`.

See [`docs/CONSENSUS.md`](docs/CONSENSUS.md).

## Equivalence rule

Validators do **not** require identical prose or identical fine-grained semantic category bits. Those can legitimately vary between independent model executions.

They do require agreement on the security facts that affect downstream behavior: reachability, hard-risk presence, literal-floor presence, parser-failure presence and the derived terminal class. A well-formed leader result that says SAFE while the validator independently observes a hard-risk source is rejected.

This is why strict byte/prose equality would be too brittle, while format-only validation would be too weak.

## Deterministic vs nondeterministic responsibility

| Deterministic contract code | Consensus-backed nondeterminism |
|---|---|
| URL/hostname admission | live source rendering |
| purpose bounds/control-channel screening | semantic machine-control classification |
| literal control-language floor | passive/relevant excerpt judgment |
| strict risk-mask parsing | |
| terminal status derivation | |
| cancellation/single-resolution rules | |
| storage/events | |
| `is_consumable` gate | |

The model reports observations. Contract code decides what those observations are allowed to become.

## Deterministic gates

### Before consensus

Ingress admits only conservative public HTTPS hostname shapes. It rejects, among other cases:

- non-HTTPS URLs;
- embedded credentials;
- explicit ports;
- localhost, `.localhost`, `.local`, and `.internal`;
- private/link-local/loopback IPv4 forms;
- numeric-only legacy IP spellings;
- leading-zero/encoded ambiguous host forms;
- malformed DNS labels;
- DNS-wrapper shapes beginning with private IPv4 prefixes;
- blank/oversized purposes;
- obvious purpose text that tries to become a second control channel.

This is defence in depth, not a claim that contract code can replace validator-network egress policy.

### During classification

- model `risk_mask` must be an integer or decimal integer string;
- booleans, floats, hex-like strings, unsupported semantic bits, and malformed output fail closed;
- obvious literal control phrases create a deterministic minimum floor;
- source and purpose are JSON-framed in prompts.

### During validator verification

- forged unknown bits are rejected;
- truthy strings cannot impersonate booleans;
- every released excerpt must be a canonical string anchored in the independent validator snapshot;
- every excerpt receives an independent passive/relevance judgment.

### After consensus

Only this path is automatically consumable:

```python
status == SAFE and len(excerpts) > 0
```

A safe classification with no grounded evidence is harmless but is not consumable evidence.

## Fail-closed matrix

| Condition | Result |
|---|---|
| Source cannot be read | `UNAVAILABLE` |
| Semantic machine-control risk | `QUARANTINED` |
| Classifier cannot be safely parsed | `QUARANTINED` |
| Deterministic literal floor only | at least `SUSPICIOUS` |
| SAFE classification but no grounded excerpt | `is_consumable == false` |
| Forged/wrongly typed leader fields | validator rejects proposal |
| Leader/validator security-class disagreement | validator rejects proposal |
| Terminal capsule resolved again | rejected |
| Non-requester cancellation | rejected |

## Public API

### `open_inspection(url, purpose) -> u256`

Creates a `PENDING` evidence capsule.

Example passive purpose:

```text
Extract factual evidence about whether ACME announced version 3.0.
```

### `resolve(capsule_id)`

Permissionless. Anyone may pay to resolve a pending capsule. Resolution is single-use.

### `cancel(capsule_id)`

Only the original requester may cancel, and only while the capsule is pending.

### `get_capsule(capsule_id) -> dict`

Returns the stored machine-readable capsule.

### `is_consumable(capsule_id) -> bool`

Preferred downstream gate. Returns true only for `SAFE` plus at least one grounded excerpt.

### `get_risk_dictionary() -> dict`

Returns the fixed diagnostic risk dictionary.

## Validation results

| Gate | Result | Evidence |
|---|---|---|
| SDK-free source preflight | PASS | `74/74` checks |
| Python source compilation | PASS | contract and deployment/preflight scripts compile |
| Direct Mode | PASS | `19 passed, 0 failed, 0 skipped` with `genlayer-test v0.29.2`, Python 3.12.13, strict mocks and pickling enabled |
| Pickling | PASS | `direct_vm.check_pickling = True` |
| GenVM linter | PASS | `genvm-lint check contracts/ingress.py --json`, genvm-linter `0.11.0`, exit `0` |
| GenLayer CLI | PASS | official CLI `0.39.2`; Studionet RPC reachable |
| Studionet deployment | PASS | finalized contract and deployment transaction recorded above |
| Live safe evidence | PASS | capsule `1`: `SAFE`, risk `0`, two grounded excerpts, consumable `true` |
| Live hostile evidence | PASS | capsule `3`: `QUARANTINED`, risk `265`, consumable `false` |

Direct Mode executed the real contract after an external, uncommitted Windows compatibility shim deferred a `genlayer-test` temporary-file cleanup bug. No contract change was needed for that harness issue.

The primary GenVM linter gate is green. Its JSON check reported `lint.ok=true` and `validate.ok=true`; only informational warning `I200` noted that a newer runner is available.

### Zero-dependency preflight

```bash
python scripts/preflight.py
```

The script reads the actual `contracts/ingress.py` source and checks structure, nondeterminism placement, absence of state writes/events inside `_inspect`, URL hardening, risk parsing, evidence anchoring, status derivation, hostile-input prompt framing and timestamp compatibility.

### Direct Mode

```bash
pip install -r requirements-test.txt
pytest tests/direct/ -v -s
```

The suite covers normal state transitions and adversarial cases including safe grounded evidence, prompt-like purpose rejection, literal and semantic attacks, malformed/fractional/hex-like risk fields, unsupported bits, invented excerpts, forged leader payloads, non-boolean reachability, security-class disagreement, cancellation and single-resolution rules.

### Optional linter

When the GenVM linter is usable in the local environment:

```bash
pip install -r requirements.txt
genvm-lint check contracts/ingress.py
```

A linter installation/tooling failure does not replace the independent preflight, Direct Mode and live Studionet evidence above.

## Studionet deployment

Ingress has no constructor arguments. For an active/unlocked GenLayer CLI account:

```bash
python scripts/deploy_studionet.py
```

Equivalent direct deployment:

```bash
genlayer deploy \
  --contract contracts/ingress.py \
  --rpc https://studio.genlayer.com/api
```

The verified deployment and every smoke transaction are recorded in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Live smoke evidence

| Action | Result |
|---|---|
| `get_risk_dictionary()` | all 10 expected entries returned |
| Open safe inspection | capsule `1`, `PENDING` |
| Open + cancel disposable inspection | capsule `2`, `CANCELLED` |
| Resolve safe public source | capsule `1`, `SAFE`, risk `0`, two grounded excerpts |
| `is_consumable(1)` | `true` |
| Resolve hostile public fixture | capsule `3`, `QUARANTINED`, risk `265` |
| `is_consumable(3)` | `false` |

The hostile fixture is [`fixtures/hostile_evidence.txt`](fixtures/hostile_evidence.txt). Transaction hashes and receipt notes are preserved in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Security properties

**Caller text is not evidence.** The source is fetched inside the nondeterministic path.

**Hostile source text is treated as data.** Source, purpose and excerpt validation values are JSON-framed before model reasoning.

**The leader cannot invent evidence.** Released excerpts must occur in an independent validator snapshot.

**Obvious control language cannot become SAFE.** A deterministic lexical floor exists outside model judgment.

**Malformed model fields fail closed.** Unsupported or ambiguous risk representations cannot silently coerce into a safe mask.

**Forged leader fields are validated.** Unknown bits, wrong types and security-dimension disagreement reject the proposal.

**The model does not directly settle state.** Deterministic code derives terminal status and the consumption gate.

**There is no privileged bypass.** No administrator can rewrite a terminal capsule or turn quarantined evidence safe.

## What Ingress does not claim

No natural-language security classifier can prove arbitrary content harmless in every future downstream context.

Ingress does not claim:

- perfect detection of every prompt-injection technique;
- protection against a malicious GenLayer validator majority;
- complete DNS-rebinding/network-level SSRF prevention;
- that `SAFE` means the factual claim is true;
- that a source is authoritative, fresh, or independent;
- that a safe excerpt is sufficient to settle a market, escrow, insurance policy, or governance action;
- inspection of content absent from GenLayer's rendered text representation.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model.

## Integration

A downstream contract should treat Ingress as an intake gate:

```text
untrusted live source
       |
       v
    Ingress
       |
       | SAFE + grounded excerpt
       v
truth / corroboration / policy / settlement primitive
```

For example, a corroboration primitive can refuse to consider a source unless `Ingress.is_consumable(capsule_id)` returns true, then independently decide whether the released factual evidence is corroborated or authoritative.

See [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Repository layout

```text
.
├── contracts/
│   └── ingress.py
├── tests/
│   └── direct/
│       ├── test_ingress.py
│       └── test_ingress_hardening.py
├── scripts/
│   ├── preflight.py
│   └── deploy_studionet.py
├── fixtures/
│   └── hostile_evidence.txt
├── docs/
│   ├── CONSENSUS.md
│   ├── SECURITY.md
│   ├── INTEGRATION.md
│   └── DEPLOYMENT.md
├── requirements-test.txt
├── requirements.txt
├── gltest.config.yaml
├── SUBMISSION.md
├── LICENSE
└── README.md
```

### Important files

| File | Purpose |
|---|---|
| [`contracts/ingress.py`](contracts/ingress.py) | canonical deployable Intelligent Contract |
| [`tests/direct/test_ingress.py`](tests/direct/test_ingress.py) | state, consensus and normal security behavior |
| [`tests/direct/test_ingress_hardening.py`](tests/direct/test_ingress_hardening.py) | forged-leader and malformed-output adversarial coverage |
| [`scripts/preflight.py`](scripts/preflight.py) | zero-dependency source/security gate |
| [`docs/CONSENSUS.md`](docs/CONSENSUS.md) | custom validator and equivalence design |
| [`docs/SECURITY.md`](docs/SECURITY.md) | threat model, guarantees and limitations |
| [`docs/INTEGRATION.md`](docs/INTEGRATION.md) | stable downstream composition surface |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | real Studionet address, transactions and smoke evidence |
| [`SUBMISSION.md`](SUBMISSION.md) | copy-ready reviewer/submission summary |

## Reviewer fast path

If you have five minutes:

1. Read the contract thesis and live deployment table at the top of this README.
2. Inspect [`contracts/ingress.py`](contracts/ingress.py), especially `_inspect`, the custom validator, terminal status derivation and `is_consumable`.
3. Inspect the forged-leader tests in [`tests/direct/test_ingress_hardening.py`](tests/direct/test_ingress_hardening.py).
4. Read [`docs/CONSENSUS.md`](docs/CONSENSUS.md) for what must agree and what may vary.
5. Read [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for real safe and hostile Studionet transactions.
6. Read [`docs/SECURITY.md`](docs/SECURITY.md) for explicit non-guarantees.

## Builder submission

**Category:** Standalone GenLayer Intelligent Contract  
**Primitive:** Ingress  
**Purpose:** consensus-backed hostile-web-evidence intake  
**Repository:** `https://github.com/ometere123/ingress`  
**Studionet contract:** `0x86506D4017B5B47Ce8Cd03b3C561E3bd96cfA0e5`

Copy-ready submission notes are in [`SUBMISSION.md`](SUBMISSION.md).

## Repository philosophy

One deployable contract, explicit consensus reasoning, fail-closed state transitions, adversarial tests, real runtime evidence, no frontend, no CI and no application-specific product flow.

That is the primitive boundary.

## Licence

MIT. See [`LICENSE`](LICENSE).
