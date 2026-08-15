from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class Category(str, Enum):
    SAST = "SAST"
    SCA = "SCA"
    SECRETS = "SECRETS"
    MISCONFIGURATION = "MISCONFIGURATION"
    VULNERABILITY = "VULNERABILITY"
    OTHER = "OTHER"
