"""High-signal live Studionet coverage for the deployed Ingress primitive.

Each test gets a fresh disposable deployment so every case is independently
runnable and never relies on pytest execution order or capsule IDs created by
another test.
"""

import pytest
from gltest import get_contract_factory, get_default_account
from gltest.assertions import tx_execution_succeeded


CONTRACT = "ingress.py"
SAFE_URL = "https://example.com/"
HOSTILE_URL = (
    "https://raw.githubusercontent.com/ometere123/ingress/main/"
    "fixtures/hostile_evidence.txt"
)
PURPOSE = "Extract factual evidence describing the declared purpose of this page."
TX_KW = {"consensus_max_rotations": 3, "wait_interval": 10000, "wait_retries": 20}

EXPECTED_RISK_DICTIONARY = {
    "PROMPT_OVERRIDE": 1,
    "ROLE_IMPERSONATION": 2,
    "TASK_REDIRECTION": 4,
    "SECRET_EXFILTRATION": 8,
    "TOOL_OR_ACTION_COMMAND": 16,
    "OBFUSCATED_INSTRUCTION": 32,
    "HIDDEN_INSTRUCTION": 64,
    "EXTERNAL_INSTRUCTION_CHAIN": 128,
    "LITERAL_CONTROL_PHRASE": 256,
    "UNPARSABLE_ANALYSIS": 512,
}


@pytest.fixture
def deployed_contract():
    factory = get_contract_factory(contract_file_path=CONTRACT)
    contract = factory.deploy(
        account=get_default_account(),
        consensus_max_rotations=3,
        wait_interval=10000,
        wait_retries=20,
    )
    assert contract.address
    return contract


def assert_success(receipt):
    assert tx_execution_succeeded(receipt), receipt


def test_deployment_and_public_read_surface(deployed_contract):
    assert deployed_contract.get_risk_dictionary().call() == EXPECTED_RISK_DICTIONARY


def test_safe_source_converges_to_consumable_evidence(deployed_contract):
    opened = deployed_contract.open_inspection([SAFE_URL, PURPOSE]).transact(**TX_KW)
    assert_success(opened)

    capsule_id = 1
    assert deployed_contract.get_capsule([capsule_id]).call()["status"] == 0

    resolved = deployed_contract.resolve([capsule_id]).transact(**TX_KW)
    assert_success(resolved)

    capsule = deployed_contract.get_capsule([capsule_id]).call()
    assert capsule["status"] == 1  # SAFE
    assert capsule["risk_mask"] == 0
    assert capsule["excerpts"]
    assert deployed_contract.is_consumable([capsule_id]).call() is True


def test_hostile_source_is_not_consumable(deployed_contract):
    opened = deployed_contract.open_inspection([HOSTILE_URL, PURPOSE]).transact(**TX_KW)
    assert_success(opened)

    capsule_id = 1
    assert deployed_contract.get_capsule([capsule_id]).call()["status"] == 0

    resolved = deployed_contract.resolve([capsule_id]).transact(**TX_KW)
    assert_success(resolved)

    capsule = deployed_contract.get_capsule([capsule_id]).call()
    assert capsule["status"] != 1  # never SAFE
    assert capsule["risk_mask"] != 0
    assert capsule["risk_mask"] & 256  # literal control phrase floor
    assert deployed_contract.is_consumable([capsule_id]).call() is False


def test_cancellation_is_terminal_and_not_consumable(deployed_contract):
    opened = deployed_contract.open_inspection(
        [SAFE_URL, "Passive cancellation verification."]
    ).transact(**TX_KW)
    assert_success(opened)

    capsule_id = 1
    assert deployed_contract.get_capsule([capsule_id]).call()["status"] == 0

    cancelled = deployed_contract.cancel([capsule_id]).transact(**TX_KW)
    assert_success(cancelled)

    capsule = deployed_contract.get_capsule([capsule_id]).call()
    assert capsule["status"] == 5  # CANCELLED
    assert deployed_contract.is_consumable([capsule_id]).call() is False
