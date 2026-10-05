from datetime import datetime
import ipaddress
from pydantic import BaseModel, Field
from .enums import *


class Target(BaseModel):
    """
    value: 192.168.0.1
    type: ip
    """
    value: str
    type: TargetType

import re
from enum import Enum


class TargetType(Enum):
    IP = "IP"
    CIDR = "CIDR"
    DOMAIN = "DOMAIN"
    URL = "URL"




def detect_target_type(value: str) -> str:
    """
    Определяет тип введённой цели.

    Пока поддерживаем:
    - IP
    - CIDR
    - DOMAIN
    - URL
    """

    value = value.strip()

    # URL
    if value.startswith(("http://", "https://")):
        return "url"

    # IP / CIDR
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    try:
        ipaddress.ip_network(value, strict=False)
        return "cidr"
    except ValueError:
        pass

    # DOMAIN
    if re.match(
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$",
        value,
    ):
        return "domain"

    raise ValueError(f"Не удалось определить тип цели: {value}")


class Asset(BaseModel):
    id: str
    type: AssetType
    value: str
    hostname: str | None = None

        


class Host(BaseModel):
    ip: str
    hostname: str | None = None

class Port(BaseModel):

    number: int = Field(ge=1, le=65535)
    protocol: Protocol = Protocol.TCP
    state: str




class Service(BaseModel):
    """
    nginx
    1.18.0
    """
    port: int = Field(ge=1, le=65535)
    protocol: Protocol
    name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None


class HTTPResult(BaseModel):
    url: str
    status_code: int
    headers: dict[str, str] = {}
    title: str | None = None
    server: str | None = None
    redirect_url: str | None = None


class TLSResult(BaseModel):
    hostname: str
    tls_version: str | None = None
    issuer: str | None = None
    subject: str | None = None
    sans: list[str] = []
    valid_from: datetime | None = None
    valid_to: datetime | None = None


class Vulnerability(BaseModel):
    """
    Это описание самой уязвимости, не конкретный результат сканирования
    """
    cve_id: str
    title: str
    description: str | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    severity: Severity | None = None
    remediation: str | None = None
    cpe: str | None = None



class ScanResult(BaseModel):
    id: int
    target: Target
    name: str | None = None
    status: str
    hosts_count: int | None = None
    ports_count: int | None = None
    findings_count: int | None = None

from pydantic import BaseModel, Field
from typing import List, Dict, Optional

class NmapPortInfo(BaseModel):
    port: int = Field(..., description="Номер TCP/UDP порта")
    state: str = Field(..., description="Состояние порта (open, closed, filtered)")
    reason: str = Field(..., description="Причина состояния (например, syn-ack)")
    service_name: str = Field(..., alias="name", description="Имя сервиса")
    product: Optional[str] = Field("", description="Название ПО")
    version: Optional[str] = Field("", description="Версия ПО")
    extrainfo: Optional[str] = Field("", description="Дополнительная информация о сервисе")
    cpe: Optional[str] = Field("", description="Идентификатор уязвимости Common Platform Enumeration")

class NmapHostReport(BaseModel):
    ip: str = Field(..., description="IPv4 или IPv6 адрес хоста")
    status: str = Field(..., description="Статус хоста (up или down)")
    hostnames: List[str] = Field(default_factory=list, description="Список привязанных доменных имен хоста")
    open_ports: List[NmapPortInfo] = Field(default_factory=list, description="Список только открытых портов")
    all_ports: List[NmapPortInfo] = Field(default_factory=list, description="Полный список просканированных портов")

class ScanAuditSummary(BaseModel):
    elapsed_time: float = Field(..., description="Время работы сканера в секундах")
    total_hosts: int = Field(..., description="Всего целей")
    up_hosts: int = Field(..., description="Активных хостов обнаружено")
    hosts: List[NmapHostReport] = Field(default_factory=list, description="Подробный отчет по каждому хосту")
