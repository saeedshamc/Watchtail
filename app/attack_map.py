"""MITRE ATT&CK mapping for the built-in detectors.

Each detector points at the ATT&CK tactic and technique it most
directly evidences. The mapping powers the IP detail page and the API
so an operator can answer "which step of the kill chain is this?"
without leaving the dashboard. IDs follow ATT&CK Enterprise v15.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackEntry:
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str


ATTACK_MAP: dict[str, AttackEntry] = {
    "ssh_bruteforce": AttackEntry(
        "Credential Access", "TA0006",
        "Brute Force: Password Guessing", "T1110.001",
    ),
    "distributed_attack": AttackEntry(
        "Credential Access", "TA0006",
        "Brute Force: Password Spraying", "T1110.003",
    ),
    "ssh_compromise": AttackEntry(
        "Defense Evasion", "TA0005",
        "Valid Accounts: Default Accounts", "T1078.001",
    ),
    "http_error_spike": AttackEntry(
        "Reconnaissance", "TA0043",
        "Active Scanning: Vulnerability Scanning", "T1595.002",
    ),
    "path_scan": AttackEntry(
        "Reconnaissance", "TA0043",
        "Active Scanning: Wordlist Scanning", "T1595.003",
    ),
    "request_burst": AttackEntry(
        "Reconnaissance", "TA0043",
        "Active Scanning", "T1595",
    ),
    "threat_intel": AttackEntry(
        "Initial Access", "TA0001",
        "Phishing / known-bad infrastructure", "T1566",
    ),
    "correlation": AttackEntry(
        "Execution", "TA0002",
        "Multi-stage operation (composite evidence)", "T1059",
    ),
    "anomaly_spike": AttackEntry(
        "Impact", "TA0040",
        "Resource saturation / abnormal volume", "T1499",
    ),
    "anomaly_silence": AttackEntry(
        "Defense Evasion", "TA0005",
        "Impair Defenses: Disable Windows Event Logging", "T1562.002",
    ),
}


def for_detector(name: str) -> AttackEntry | None:
    return ATTACK_MAP.get(name)


def describe(name: str) -> dict | None:
    entry = ATTACK_MAP.get(name)
    if entry is None:
        return None
    return {
        "tactic": entry.tactic,
        "tactic_id": entry.tactic_id,
        "technique": entry.technique,
        "technique_id": entry.technique_id,
    }


def all_described() -> dict[str, dict]:
    return {name: describe(name) for name in ATTACK_MAP}
