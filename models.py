from pydantic import BaseModel, Field

class LogPayload(BaseModel):
    source: str = Field(..., description="Source system e.g. FortiGate")
    event_type: str
    payload: str
    severity_level: str = "INFO"

class SystemConfig(BaseModel):
    firewall_remote_management: bool
    m365_mfa_enforced: bool
    default_admin_account_active: bool