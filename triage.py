
from datetime import datetime

class AlertTriage:
    def __init__(self, source, event_type, payload):
        self.source = source
        self.event_type = event_type
        self.payload = payload
        self.timestamp = datetime.now()

    def calculate_risk_score(self):
        score = 0
        # Keyword-based risk heuristic
        if "brute-force" in self.payload.lower() or "unauthorized" in self.payload.lower():
            score += 40
        if "admin" in self.payload.lower() or "root" in self.payload.lower():
            score += 30
        if self.source == "FortiGate" and "DENY" in self.payload:
            score += 20
        else:
            score += 10
            
        return min(score, 100) # Cap at 100

    def evaluate_priority(self):
        score = self.calculate_risk_score()
        if score >= 75:
            return "HIGH - Immediate Response Required"
        elif score >= 40:
            return "MEDIUM - Review within 24 Hours"
        else:
            return "LOW - Informational Log"

# Test the triage module
if __name__ == "__main__":
    test_alert = AlertTriage(
        source="FortiGate",
        event_type="Firewall Drop",
        payload="DENY src=45.33.32.156 dst=10.0.0.15 proto=TCP dpt=3389 (Brute-force pattern on admin port)"
    )
    
    print("=== SOC Alert Triage Engine ===")
    print(f"Source: {test_alert.source}")
    print(f"Event: {test_alert.event_type}")
    print(f"Calculated Risk Score: {test_alert.calculate_risk_score()}/100")
    print(f"Priority Level: {test_alert.evaluate_priority()}")
