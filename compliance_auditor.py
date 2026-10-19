
import json

# Simulated system configuration or log scan results
system_scan_data = {
    "firewall_remote_management": True, # Risk: Open to the world
    "m365_mfa_enforced": False,         # Risk: Non-compliant with ISO 27001 Access Control
    "default_admin_account_active": True # Risk: High security vulnerability
}

# Compliance Control Framework mapping
iso_27001_controls = {
    "A.9.1.1": {
        "title": "Access Control Policy",
        "check": lambda data: data["m365_mfa_enforced"] == True,
        "remediation": "Enforce Multi-Factor Authentication (MFA) across all M365 user and admin accounts."
    },
    "A.12.1.2": {
        "title": "Change Management & Hardening",
        "check": lambda data: data["firewall_remote_management"] == False and data["default_admin_account_active"] == False,
        "remediation": "Disable external remote management on firewalls and rename/disable default admin accounts."
    }
}

def audit_environment(data):
    print("=== GRC Automated Compliance Audit Report ===")
    compliance_score = 0
    total_checks = len(iso_27001_controls)
    
    for control_id, control in iso_27001_controls.items():
        is_passed = control["check"](data)
        status = "COMPLIANT" if is_passed else "NON_COMPLIANT [FLAGGED]"
        
        if is_passed:
            compliance_score += 1
            
        print(f"\nControl [{control_id}] - {control['title']}")
        print(f"Status: {status}")
        if not is_passed:
            print(f"Action Required: {control['remediation']}")
            
    print("\n" + "="*45)
    print(f"Overall Compliance Health: {(compliance_score / total_checks) * 100}%")

if __name__ == "__main__":
    audit_environment(system_scan_data)
