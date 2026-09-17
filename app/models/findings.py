from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Higher weight = more impact on the health score
SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 10,
    Severity.CRITICAL: 20,
}


class Category(str, Enum):
    SECURITY = "Security"
    NETWORKING = "Networking"
    ROUTING = "Routing"
    AVAILABILITY = "Availability"
    MANAGEMENT = "Management"
    PERFORMANCE = "Performance"
    CONFIG_QUALITY = "Configuration quality"
    BEST_PRACTICES = "Best practices"


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    vendor: str
    category: Category
    title: str
    description: str
    recommendation: str
    subject: str | None = None  # e.g. interface name, ACL name - what the finding is about
