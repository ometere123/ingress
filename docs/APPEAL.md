# Appeal — Ingress: Consensus Firewall for Hostile Web Evidence

Contribution ID `023575bc…` · Intelligent Contracts · reviewed 2026-08-21

---

## PART 1 — Paste into the appeal field

**We do not contest the finding. It was correct, and it was precise.**

The reviewer identified that `validator_fn` accepted an empty leader excerpt list unconditionally while `is_consumable` is `status == SAFE and len(excerpts) > 0`. That made the emptiness of that list the one consensus-visible field no validator examined, so the same SAFE inspection could settle consumable or non-consumable on an unverified leader choice. That is a genuine consensus-soundness defect. We are not appealing the diagnosis.

We are appealing the disposition: we ask that the corrected artifact be re-reviewed under this contribution rather than requiring a fresh submission, for three reasons we believe are checkable rather than rhetorical.

**1. The submission did not misrepresent what it verified.**

The rejected version's documentation claimed that *every released excerpt* was anchored to the validator's own snapshot and independently judged passive and relevant. That claim was true. Its consensus-equivalence list said "source anchoring and passive/relevance of **every released excerpt**" — accurately scoped. It stated that an empty-evidence SAFE capsule is not consumable, and explicitly warned integrators that treating one as trusted evidence defeats the primitive.

So this was an unbound degree of freedom that the documentation did not cover in either direction — not a false claim about a check that did not exist. Verifiable at commit `12bcc2e`, `docs/SECURITY.md` lines 50 and 63, and `docs/CONSENSUS.md` line 128.

**2. Evidence integrity was already validator-bound; availability was not.**

In the rejected contract every released excerpt was independently required to be a canonical bounded string, present in the validator's **own** rendered snapshot, and to pass the validator's own passive/relevance judgment. The terminal security class was independently derived and compared. Those were not format checks.

The consequence is that the defect's exploitable direction was **evidence suppression** — a leader could make a capsule non-consumable — and never admission of hostile or ungrounded content, because consumability requires a non-empty list and every released excerpt was already bound.

We do not offer this as exoneration. Suppression is a real attack: a leader with a stake in a downstream market could withhold evidence to stall settlement, which is exactly why the fix was necessary. We offer it as severity calibration, because it is a distinct class from the failure the primitive exists to prevent — hostile page text reaching a downstream model as trusted evidence. That failure mode was not reachable through this defect.

**3. The remedy implements both options the review offered, and was tested for over-correction.**

The review asked us to "bind excerpt availability, or derive consumability from their own observation." One shared acceptance test does both:

| Leader proposed | Validator requirement |
|---|---|
| one or more excerpts | each grounded in the validator's own snapshot **and** passing its own release judgment |
| nothing | **no** grounded candidate in its own snapshot passes that same release judgment |

The invariant is now total: *a capsule is non-consumable only when validators independently observed nothing releasable.* Consumability is derived from validator observation, not leader discretion.

We deliberately reused the strict release judgment rather than a looser "was anything relevant here" probe, and added two over-rejection guards, because a naive fix rejects honest leaders on pages that genuinely hold nothing releasable. Engaging with that trade-off was part of taking the finding seriously rather than pattern-matching it.

**Verifiable now, independently of our claims:**

- Redeployed at `0xdd641B5bdBE8D9C14783b458425da180946Fe41c`, tx `0x4e3dda32…`, `FINALIZED` / `MAJORITY_AGREE`. `genlayer code` returns a source byte-for-byte identical to `contracts/ingress.py` — parity verified against the chain, not asserted.
- `test_validator_rejects_leader_that_withholds_available_evidence` fails against the rejected contract and passes against the corrected one.
- Preflight 86/86, Direct Mode 26/26, Studionet integration 4/4, `genvm-linter` exit 0.
- The prior address `0x86506D40…` is retained in the docs as an explicit superseded-evidence note, not presented as current.

The review found the one thing that mattered, and it made the fix precise. We are asking for re-review of the corrected artifact, not for the original to be accepted as it stood.

---

## PART 2 — Supporting annex (attach or link if the form allows)

### What the rejected contract did and did not bind

| Property | Rejected version | Corrected version |
|---|---|---|
| Reachability agreement | validator-bound | unchanged |
| Risk-mask type / unknown-bit rejection | validator-bound | unchanged |
| Terminal security class | independently derived and compared | unchanged |
| Released excerpt is canonical and bounded | validator-bound | unchanged |
| Released excerpt grounded in validator's own snapshot | validator-bound | unchanged |
| Released excerpt passive and relevant | independently judged | unchanged |
| Excerpt permitted only on a SAFE class | **not enforced** | enforced by `excerpts_for_class`, shared by observation, validation and settlement |
| **Whether releasable evidence existed at all** | **not bound — the defect** | bound by `judge_excerpt_release` on the validator's own candidates |

### The exact change

`contracts/ingress.py`:

- `judge_excerpt_release(excerpt, purpose) -> bool` — one acceptance test, applied to excerpts the leader released *and* to grounded candidates the leader withheld, so releasing and withholding are judged by identical criteria.
- `validator_fn` — a SAFE proposal with an empty list is accepted only when no grounded candidate in the validator's own snapshot passes that test.
- `excerpts_for_class(excerpts, mask)` — shared by the leader observation path, the validator and settlement. Evidence rides on SAFE only. This was structurally required, not cosmetic: without it, honest leaders classifying a risky source would be rejected by the new non-SAFE rule.

### Regression evidence

Four negative regressions confirmed to fail against the rejected contract and pass against the corrected one:

- `test_validator_rejects_leader_that_withholds_available_evidence`
- `test_validator_rejects_released_excerpt_that_fails_release_test`
- `test_validator_rejects_evidence_attached_to_risky_observation`
- `test_risky_capsule_stores_no_excerpts_even_when_model_returns_them`

Two over-rejection guards that pass against both versions, demonstrating the fix does not punish honest empty results:

- `test_validator_accepts_empty_evidence_when_it_observes_none`
- `test_validator_accepts_empty_evidence_when_candidate_fails_release_test`

Twelve new source-level preflight checks assert via AST that `validator_fn` consults its own excerpt observation, applies `judge_excerpt_release` in both directions, and branches on an empty leader list — so the property cannot silently regress.

### Live evidence for the corrected behaviour

Two safe resolutions on the new deployment reached `MAJORITY_AGREE` **with** a grounded excerpt and `is_consumable == true`:

- `0xe14bc74309ca33ef4ee4a9d818a62aeb47337c6469c6ce90ee20292ac283463c` (capsule 4)
- `0x3cbf2a3be553f54eb63eb708c47474adea975207f938066c94b2616847e27174` (capsule 1)

Five validators independently rendered the source, judged the excerpt releasable, and agreed releasable evidence existed. Under the rejected contract that same page could have settled non-consumable with no validator objecting.

The hostile resolve `0x51f620aed7343bcd54d0c7a8561ceaeb82e4a58f07d462e9caa8511a17adb537` settled `QUARANTINED`, risk `265`, storing `excerpts: []` — the class-bound rule confirmed on chain.

Note that the two safe capsules settled on slightly different grounded spans. That is the limitation we state explicitly in `docs/SECURITY.md`: the binding constrains whether releasable evidence *existed*, not which releasable span a leader selects. Every selection remains independently grounded and judged. We document that boundary rather than claim a stronger property than we implement.

### Stated limitations, unchanged in candour

- Binds availability, not selection.
- On genuinely borderline pages honest models can disagree about availability; the proposal is then rejected and the capsule stays `PENDING` rather than settling unverified.
- No protection against a malicious validator majority.
- No claim of complete prompt-injection detection or network-level SSRF prevention.
