# Ingress

**A reusable GenLayer Intelligent Contract that screens hostile web content before another contract or agent is allowed to treat it as evidence.**

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

## Why Ingress exists

GenLayer Intelligent Contracts can read the live web and use LLMs to interpret what they read. That creates a security boundary ordinary oracle designs do not have: a source can contain a useful fact and, in the same content, contain text intended to control the model reading it.

Examples include instructions to ignore governing prompts, impersonate system authority, expose secrets, call tools, transact, download something, or follow another page for further instructions.

If every builder implements this defence independently, downstream contracts inherit inconsistent and difficult-to-review prompt-injection handling. Ingress makes evidence intake a composable primitive.

Ingress does **not** claim to sanitise the internet or prove that a factual claim is true. Its narrower question is:

> Can this web source be released forward as passive evidence without the source itself attempting to control the model or agent reading it?

Truth corroboration, freshness, authority, policy evaluation, and settlement remain separate composable layers.

## Why this needs GenLayer

A central content-safety API simply replaces one trust problem with another operator.

Ingress needs all three of these properties:

1. **live web access** so validators observe the source rather than trusting caller-supplied text;
2. **semantic reasoning** because machine-directed manipulation cannot be completely reduced to substring rules;
3. **independent consensus** so a single model invocation cannot decide what another contract may trust.

The leader proposes an observation. Validators independently fetch and classify the source before accepting it.

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
requirements-test.txt            Direct Mode deps, intentionally no linter
requirements.txt                 optional full tooling, including linter
docs/CONSENSUS.md                custom validator design
docs/SECURITY.md                 threat model and limitations
docs/INTEGRATION.md              downstream composition example
SUBMISSION.md                    reviewer-oriented summary
gltest.config.yaml               GenLayer test configuration
```

No frontend is required or intended for this standalone Intelligent Contract submission.

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

The semantic classifier uses these fixed bits:

| Bit | Name | Meaning |
|---:|---|---|
| `1` | `PROMPT_OVERRIDE` | tries to replace governing instructions |
| `2` | `ROLE_IMPERSONATION` | claims system/developer/assistant authority |
| `4` | `TASK_REDIRECTION` | redirects the evidence task |
| `8` | `SECRET_EXFILTRATION` | requests hidden prompts, credentials, keys, or secrets |
| `16` | `TOOL_OR_ACTION_COMMAND` | asks the reader to execute code, call tools, transact, message, download, or otherwise act |
| `32` | `OBFUSCATED_INSTRUCTION` | disguised machine-directed instruction |
| `64` | `HIDDEN_INSTRUCTION` | non-visible machine-directed instruction represented in the rendered text |
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

The LLM never writes `SAFE`, `SUSPICIOUS`, or `QUARANTINED` directly.

### Important integration rule about the bitmask

The individual semantic category bits are **diagnostic labels**, not a stable settlement API. Two honest validators can recognise the same malicious source but categorise it as different hard-risk bits.

Consensus therefore requires agreement on security-relevant dimensions:

- source reachability;
- whether any semantic hard risk is present;
- whether the deterministic literal floor is present;
- whether analysis failed to parse safely;
- the derived terminal security class.

Downstream automatic decisions should use `status` or, preferably, `is_consumable()`. Do not make payout logic depend on one exact semantic category bit.

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

The hostile page is never interpolated as an instruction section. It is JSON-encoded as a data value.

### Validator

Each validator independently:

1. renders the URL itself;
2. classifies its own source snapshot;
3. requires typed `bool` reachability and bounded integer risk fields from the leader;
4. rejects unknown risk bits or malformed leader fields;
5. checks security-relevant risk dimensions and the derived class independently agree;
6. uses the **same validator snapshot** for classification and excerpt grounding, avoiding a second-fetch time-of-check/time-of-use gap;
7. requires every leader excerpt to be a canonical bounded string present in that validator snapshot;
8. independently judges each released excerpt as passive and relevant to the caller purpose.

The validator is therefore not a JSON/schema checker. A well-formed but substantively different leader proposal is rejected.

See [`docs/CONSENSUS.md`](docs/CONSENSUS.md).

## Deterministic gates

### Before consensus

Ingress admits only conservative public HTTPS hostname shapes. It rejects, among other cases:

- non-HTTPS URLs;
- embedded credentials;
- explicit ports;
- localhost, `.localhost`, `.local`, and `.internal`;
- ordinary private/link-local/loopback IPv4 forms;
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
- each excerpt receives an independent passive/relevance judgment.

### After consensus

Only this path is automatically consumable:

```python
status == SAFE and len(excerpts) > 0
```

A safe classification with no grounded evidence is harmless but not useful evidence.

## Public API

### `open_inspection(url, purpose) -> u256`

Creates a `PENDING` evidence capsule.

Example purpose:

```text
Extract factual evidence about whether ACME announced version 3.0.
```

The purpose is a bounded relevance description, not an arbitrary model prompt.

### `resolve(capsule_id)`

Permissionless. Anyone may pay to resolve a pending capsule. Resolution is single-use.

### `cancel(capsule_id)`

Only the original requester may cancel, and only while the capsule is pending.

### `get_capsule(capsule_id) -> dict`

Returns the stored machine-readable capsule.

### `is_consumable(capsule_id) -> bool`

The preferred downstream safety gate. Returns true only for `SAFE` plus at least one grounded excerpt.

### `get_risk_dictionary() -> dict`

Returns the fixed diagnostic risk dictionary.

## Testing without `genvm-lint`

## Validation results for this checkout

| Gate | Result | Evidence |
|---|---|---|
| SDK-free source preflight | PASS | `74/74` checks |
| Python source compilation | PASS | contract and deployment/preflight scripts compile |
| Direct Mode | PASS | `19 passed` with `genlayer-test v0.29.2`, Python 3.12.13, strict mocks, and pickling checks enabled; a temporary external Windows unlink shim was required for the harness bug |
| GenVM linter | ENVIRONMENT BLOCKED | `genvm-linter v0.11.0` source installation did not produce an installed package/CLI in this runtime; no pass is claimed |
| GenLayer CLI | PASS | official CLI `0.39.2` installed; Studionet selected; RPC reachable |
| Studionet deployment | BLOCKED ON ACCOUNT | CLI secure store contains no accounts; no transaction or address is claimed |

Direct Mode executed the contract successfully after an external, uncommitted Windows compatibility shim deferred the harness's unlink of an fd-0 temp file. Deployment evidence is not included because the official CLI has no configured account in this environment.

The linter is **not** required to run the primary test path.

### 1. Zero-dependency preflight

Uses only Python's standard library and reads the exact contract source:

```bash
python scripts/preflight.py
```

It checks contract structure, nondeterminism placement, absence of state writes/events inside `_inspect`, URL hardening, risk parsing, evidence anchoring, status derivation, and hostile-input prompt framing.

### 2. Direct Mode

Install only the compatible test suite:

```bash
pip install -r requirements-test.txt
```

Then run:

```bash
pytest tests/direct/ -v -s
```

The Direct Mode suite covers normal state transitions and adversarial cases including:

- safe grounded evidence;
- prompt-like purpose rejection;
- literal and semantic attacks;
- malformed/fractional/hex-like risk fields;
- unsupported risk bits;
- invented excerpts;
- forged leader payloads;
- non-boolean reachability;
- leader/validator security-class disagreement;
- cancellation and single-resolution rules.

The forged-leader tests use `direct_vm.run_validator(leader_result=...)`, so they exercise the validator against a deliberately malicious proposal rather than only against malformed model output.

### 3. Optional linter

When the GenVM linter and its SDK artifact are available:

```bash
pip install -r requirements.txt
genvm-lint check contracts/ingress.py
```

A linter installation/artifact failure should not prevent the independent preflight and Direct Mode paths above from running.

## Studionet deployment

Ingress has no constructor arguments.

If the GenLayer CLI already has an active/unlocked account, the repository provides:

```bash
python scripts/deploy_studionet.py
```

The launcher:

1. runs the zero-dependency preflight;
2. shows the active CLI account;
3. deploys the exact `contracts/ingress.py` file to the Studionet RPC;
4. never accepts, reads, or stores a private key;
5. does not invoke `genvm-lint`.

Equivalent direct CLI deployment:

```bash
genlayer deploy \
  --contract contracts/ingress.py \
  --rpc https://studio.genlayer.com/api
```

After deployment, exercise real writes and inspect any failing transaction receipt/trace before changing contract logic.

## Security properties

Ingress is designed so that:

**Caller text is not evidence.** The source is fetched inside the non-deterministic path.

**Hostile source text is treated as data.** Source, purpose, and excerpt validation values are JSON-framed before model reasoning.

**The leader cannot invent evidence.** Released excerpts must occur in an independent validator snapshot.

**Obvious control language cannot become SAFE.** A small deterministic lexical floor exists outside model judgment.

**Malformed model fields fail closed.** Unsupported or ambiguous risk representations cannot silently coerce into a safe mask.

**Forged leader fields are validated.** Unknown bits, wrong types, and security-dimension disagreement reject the proposal.

**The model does not directly settle state.** Ordinary code derives terminal status and the consumption gate.

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

See [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Repository philosophy

One deployable contract, explicit consensus reasoning, fail-closed state transitions, adversarial tests, no frontend, no CI, and no application-specific product flow.

That is the primitive boundary.

## Licence

MIT. See [`LICENSE`](LICENSE).
