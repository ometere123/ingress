"""Focused regressions for security hardening added after the first build."""

import json

CONTRACT = "contracts/ingress.py"
URL = "https://example.com/release"
PURPOSE = "Extract evidence about whether ACME released version 3.0."
CLASSIFIER = r"You are a security classifier for untrusted web evidence"

SAFE_PAGE = "ACME released version 3.0 on 14 August 2026."


def mock_safe_without_excerpts(direct_vm):
    direct_vm.mock_web(r".*example\.com/release.*", {"status": 200, "body": SAFE_PAGE})
    direct_vm.mock_llm(
        CLASSIFIER,
        json.dumps(
            {
                "risk_mask": 0,
                "reason": "no machine-control instruction detected",
                "excerpts": [],
            }
        ),
    )


def capture_safe_validator(direct_vm, contract):
    mock_safe_without_excerpts(direct_vm)
    capsule_id = contract.open_inspection(URL, PURPOSE)
    contract.resolve(capsule_id)
    assert contract.get_capsule(capsule_id)["status"] == 1


def test_fractional_risk_mask_fails_closed(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT)
    direct_vm.mock_web(r".*example\.com/release.*", {"status": 200, "body": SAFE_PAGE})
    direct_vm.mock_llm(
        CLASSIFIER,
        json.dumps(
            {
                "risk_mask": 1.5,
                "reason": "invalid fractional risk value",
                "excerpts": [],
            }
        ),
    )

    capsule_id = contract.open_inspection(URL, PURPOSE)
    contract.resolve(capsule_id)

    capsule = contract.get_capsule(capsule_id)
    assert capsule["status"] == 3
    assert "UNPARSABLE_ANALYSIS" in capsule["risk_names"]
    assert capsule["consumable"] is False


def test_hex_like_risk_mask_fails_closed(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT)
    direct_vm.mock_web(r".*example\.com/release.*", {"status": 200, "body": SAFE_PAGE})
    direct_vm.mock_llm(
        CLASSIFIER,
        json.dumps(
            {
                "risk_mask": "0x10",
                "reason": "ambiguous numeric representation",
                "excerpts": [],
            }
        ),
    )

    capsule_id = contract.open_inspection(URL, PURPOSE)
    contract.resolve(capsule_id)

    capsule = contract.get_capsule(capsule_id)
    assert capsule["status"] == 3
    assert "UNPARSABLE_ANALYSIS" in capsule["risk_names"]
    assert capsule["consumable"] is False


def test_validator_rejects_unknown_bits_from_forged_leader(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT)
    capture_safe_validator(direct_vm, contract)

    direct_vm.clear_mocks()
    mock_safe_without_excerpts(direct_vm)

    forged = {
        "reachable": True,
        "risk_mask": 4096,
        "reason": "forged unknown risk bit",
        "excerpts": [],
    }
    assert direct_vm.run_validator(leader_result=forged) is False


def test_validator_rejects_non_boolean_reachability(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT)
    capture_safe_validator(direct_vm, contract)

    direct_vm.clear_mocks()
    mock_safe_without_excerpts(direct_vm)

    forged = {
        "reachable": "true",
        "risk_mask": 0,
        "reason": "wrong field type",
        "excerpts": [],
    }
    assert direct_vm.run_validator(leader_result=forged) is False


def test_validator_rejects_boolean_risk_mask(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT)
    capture_safe_validator(direct_vm, contract)

    direct_vm.clear_mocks()
    mock_safe_without_excerpts(direct_vm)

    forged = {
        "reachable": True,
        "risk_mask": True,
        "reason": "bool is not an integer risk mask",
        "excerpts": [],
    }
    assert direct_vm.run_validator(leader_result=forged) is False
