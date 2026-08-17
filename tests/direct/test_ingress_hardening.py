"""Focused regressions for security hardening added after the first build."""

import json

CONTRACT = "contracts/ingress.py"
URL = "https://example.com/release"
PURPOSE = "Extract evidence about whether ACME released version 3.0."
CLASSIFIER = r"You are a security classifier for untrusted web evidence"

SAFE_PAGE = "ACME released version 3.0 on 14 August 2026."


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
