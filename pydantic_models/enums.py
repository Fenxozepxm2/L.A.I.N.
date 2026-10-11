from enum import Enum


class TargetType(str, Enum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class VerificationStatus(str, Enum):
    POTENTIAL = "potential"
    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    ERROR = "error"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RelationType(str, Enum):
    RESOLVES_TO = "resolves_to"
    CNAME_TO = "cname_to"
    HOSTS = "hosts"
    EXPOSES = "exposes"
    RUNS = "runs"
    USES = "uses"
    CERTIFICATE_FOR = "certificate_for"
    AFFECTED_BY = "affected_by"

class AssetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    HOST = "host"
    SERVICE = "service"
    CERTIFICATE = "certificate"
    VULNERABILITY = "vulnerability"