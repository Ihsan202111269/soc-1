
from compliance_auditor import audit_environment, system_scan_data
from triage import AlertTriage

def run_soc_pipeline():
    print("==================================================")
    print("      SOC-1 AUTOMATED SEC-OPS & GRC PIPELINE      ")
    print("==================================================\n")
    
    # 1. Run GRC Compliance Check
    audit_environment(system_scan_data)
    
    print("\n" + "="*50 + "\n")
    
    # 2. Run Alert Triage Simulation
    sample_alert = AlertTriage(
        source="FortiGate",
        event_type="Firewall Incursion Attempt",
        payload="DENY src=203.0.113.55 dst=10.0.0.5 proto=TCP dpt=3389 (Unauthorized admin access scan)"
    )
    
    print("=== Real-Time Alert Triage Feed ===")
    print(f"Source System: {sample_alert.source}")
    print(f"Event Description: {sample_alert.event_type}")
    print(f"Risk Assessment Score: {sample_alert.calculate_risk_score()}/100")
    print(f"Assigned Priority: {sample_alert.evaluate_priority()}")
    print("==================================================")

if __name__ == "__main__":
    run_soc_pipeline()