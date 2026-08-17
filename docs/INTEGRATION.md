# Integrating Ingress

Ingress is designed to sit before any contract logic that would otherwise place untrusted web text into a non-deterministic reasoning prompt.

## Minimal flow

```text
1. open_inspection(url, purpose)
2. resolve(capsule_id)
3. require is_consumable(capsule_id)
4. read get_capsule(capsule_id)["excerpts"]
5. use only those bounded excerpts as downstream evidence
```

Do not treat `status == SAFE` alone as a complete evidence gate. A SAFE source with no purpose-relevant, source-anchored excerpt is intentionally not consumable.

## Cross-contract interface

The deployable contract exports `IIngress`:

```python
@gl.contract_interface
class IIngress:
    class View:
        def get_capsule(self, capsule_id: u256) -> dict: ...
        def is_consumable(self, capsule_id: u256) -> bool: ...
        def get_risk_dictionary(self) -> dict: ...

    class Write:
        def open_inspection(self, url: str, purpose: str) -> u256: ...
        def resolve(self, capsule_id: u256) -> None: ...
        def cancel(self, capsule_id: u256) -> None: ...
```

A downstream contract can declare the same interface locally and call the deployed Ingress address.

## Example: evidence-gated settlement

The following is intentionally documentation code rather than another `.py` file under `contracts/`. Keeping only one deployable contract in this repository prevents automated review tools from treating composition examples as additional contract submissions.

```python
@gl.public.write
def accept_ingress_evidence(self, ingress_address: Address, capsule_id: u256):
    ingress = IIngress(ingress_address)

    if not ingress.view().is_consumable(capsule_id):
        raise gl.vm.UserError("Ingress capsule is not safe consumable evidence")

    capsule = ingress.view().get_capsule(capsule_id)
    excerpts = capsule["excerpts"]

    # Only now may the downstream primitive perform its own domain-specific
    # reasoning over the bounded evidence.
    # Example: corroborate a release date, evaluate an SLA clause, etc.
```

The exact cross-contract invocation syntax should follow the GenLayer SDK version used by the consuming repository. The important architectural rule is the gate, not this illustrative wrapper.

## Stable purpose templates

Prefer application-defined purposes such as:

```text
Extract factual evidence stating the announced release date of ACME version 3.0.
```

or:

```text
Extract factual evidence stating whether the service status page reports an outage.
```

Avoid exposing `purpose` as an arbitrary prompt box. Even though Ingress rejects obvious control language, application-defined templates keep the security boundary much smaller.

## Composing with other primitives

Ingress answers source-safety, not truth.

A strong composition can therefore be:

```text
web URL
  |
  v
Ingress                  source tries to control reader?
  |
  | SAFE + anchored evidence only
  v
SourceQuorum             independently corroborated?
  |
  v
Policy / settlement      does the corroborated fact satisfy the rule?
```

Other valid compositions include:

```text
Ingress -> SemanticWatcher
Ingress -> dependency drift detector
Ingress -> deliverable acceptance primitive
Ingress -> prediction-market resolver
Ingress -> insurance trigger
Ingress -> agent conformance checker
```

Ingress should remain ignorant of every one of those application domains.

## Versioning

A production consumer should pin:

- a deployed Ingress contract address;
- the risk dictionary expected by that integration;
- the semantic meaning of `is_consumable`.

If a future Ingress version expands its observation surface, risk taxonomy, or validator policy, deploy it as a new version rather than silently changing the meaning of already-issued capsules.

## Consumption checklist

- Use an application-defined passive purpose.
- Resolve the capsule before use.
- Require `is_consumable == true`.
- Consume only `excerpts`, never re-fetch and blindly pass the whole source downstream.
- Apply truth/corroboration/freshness checks separately.
- Do not add an admin override that turns a failed Ingress result into trusted evidence.
