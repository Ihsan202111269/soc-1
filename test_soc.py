# test_soc.py
from triage import AlertTriage
from compliance_auditor import audit_environment, system_scan_data

def test_high_risk_triage():
    alert = AlertTriage(
        source="FortiGate",
        event_type="Incursion",
        payload="DENY brute-force attack on admin port"
    )
    score = alert.calculate_risk_score()
    assert score >= 40, "Risk score should be elevated for brute-force patterns."
    assert alert.evaluate_priority() != "LOW - Informational Log"

def test_compliance_structure():
    # Ensure system scan data contains expected keys
    assert "m365_mfa_enforced" in system_scan_data
    assert "firewall_remote_management" in system_scan_data