import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .enums import *


class Target(BaseModel):
    """
    value: 192.168.0.1
    type: ip
    """

    value: str
    type: TargetType

SECURITY_HEADERS: dict[str, str] = {
        "Strict-Transport-Security": "Защита от снижения шифрования (HSTS)",
        "Content-Security-Policy": "Защита от XSS и инъекций контента (CSP)",
        "X-Frame-Options": "Защита от кликджекинга (Clickjacking)",
        "X-Content-Type-Options": "Защита от MIME-sniffing атак",
    }





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


class IpList(BaseModel):
    """
    [{'ip_addres': '104.154.89.105', 'ip_version': 'IPv4', 'real_name': 'badssl.com'}]
    """

    items: list[dict[str, str]]


class WebService(BaseModel):
    """Найденный веб-сервис: то, что отдаёт find_web_services()."""

    ip: str
    port: int = Field(ge=1, le=65535)
    service: str | None = None


class Host(BaseModel):
    ip: str
    hostname: str | None = None


class ActiveHost(BaseModel):
    """
    [{'ip_addres': '104.154.89.105', 'state': 'up'}]
    """

    all_active_hosts: list[dict[str, str]]


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

    model_config = ConfigDict(populate_by_name=True)

    https_redirect: str | None = Field(default=None, alias="HTTPS-Redirect")
    content_security_policy: str | None = Field(
        default=None, alias="Content-Security-Policy"
    )
    x_frame_options: str | None = Field(default=None, alias="X-Frame-Options")
    strict_transport_security: str | None = Field(
        default=None, alias="Strict-Transport-Security"
    )
    x_content_type_options: str | None = Field(
        default=None, alias="X-Content-Type-Options"
    )
    referrer_policy: str | None = Field(default=None, alias="Referrer-Policy")
    server: str | None = Field(default=None, alias="Server")

    def issues(self, is_https: bool = True) -> dict[str, str]:
        """Только реальные замечания {название: текст}. HSTS по HTTP не считается (RFC 6797)."""
        found: dict[str, str] = {}
        for attr, field in type(self).model_fields.items():
            title = field.alias or attr
            text = getattr(self, attr)
            if not text:
                continue
            if title == "Strict-Transport-Security" and not is_https:
                continue
            found[title] = text
        return found


class HTTPResult(BaseModel):
    url: str
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    title: str | None = None
    server: str | None = None
    redirect_url: str | None = None
    findings: ScanResult = Field(default_factory=ScanResult)



class TargetScanInfo(BaseModel):
    ip: str
    port: int
    scheme: Literal["http", "https"] = "http"
    headers: dict[str, str] = Field(default_factory=dict)
    result: ScanResult | None = None
    error: str | None = None

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    def header(self, name: str) -> str | None:
        """Значение заголовка без учёта регистра."""
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None


    def applicable_security_headers(self) -> dict[str, str]:
        """Заголовки, применимые к этой схеме (HSTS только для HTTPS)."""
        return {
            name: desc
            for name, desc in SECURITY_HEADERS.items()
            if self.is_https or name != "Strict-Transport-Security"
        }

    def missing_security_headers(self) -> list[str]:
        return [
            name for name in self.applicable_security_headers() if not self.header(name)
        ]


class HttpProbe(BaseModel):
    """Итог одного HTTP-запроса: что ответил сервер и что нашёл анализ."""

    headers: dict[str, str] = Field(default_factory=dict)  # сырые заголовки ответа
    findings: ScanResult = Field(default_factory=ScanResult)

class TlsVersionResult(BaseModel):
    version: str = Field(..., description="Версия протокола (например, tls_1_2)")
    accepted_ciphers: list[str] = Field(
        ..., description="Список принятых сервером шифров"
    )


# Модель с подробными данными о SSL-сертификате
class CertificateInfoResult(BaseModel):
    subject: str = Field(..., description="Кому выдан сертификат (Common Name)")
    issuer: str = Field(..., description="Кем выдан сертификат (Удостоверяющий центр)")
    is_valid: bool = Field(
        ..., description="Является ли сертификат валидным на момент проверки"
    )
    key_type: str = Field(..., description="Тип алгоритма ключа (RSA или ECDSA)")
    key_size: int | None = Field(
        None, description="Размер ключа в битах (например, 2048)"
    )
    fingerprint_sha256: str = Field(
        ..., description="Уникальный SHA-256 отпечаток сертификата"
    )
    not_before: str | None = Field(
        None, description="Дата начала действия в ISO формате"
    )
    not_after: str | None = Field(
        None, description="Дата окончания действия в ISO формате"
    )
    validation_errors: list[str] = Field(
        default_factory=list, description="Список ошибок валидации"
    )


# Главная мастер-модель, объединяющая весь скан
class AllTlsScanResult(BaseModel):
    target_host: str = Field(..., description="Сканируемый домен или IP-адрес")
    ciphers: list[TlsVersionResult] = Field(
        ..., description="Результаты сканирования TLS-протоколов"
    )
    certificate: CertificateInfoResult | None = Field(
        None, description="Данные о сертификате сервера"
    )


from pydantic import BaseModel, Field


class NmapPortInfo(BaseModel):
    port: int = Field(..., description="Номер TCP/UDP порта")
    state: str = Field(..., description="Состояние порта (open, closed, filtered)")
    reason: str = Field(..., description="Причина состояния (например, syn-ack)")
    service_name: str = Field(..., alias="name", description="Имя сервиса")
    product: str | None = Field("", description="Название ПО")
    version: str | None = Field("", description="Версия ПО")
    extrainfo: str | None = Field("", description="Дополнительная информация о сервисе")
    cpe: str | None = Field(
        "", description="Идентификатор уязвимости Common Platform Enumeration"
    )


class NmapHostReport(BaseModel):
    ip: str = Field(..., description="IPv4 или IPv6 адрес хоста")
    status: str = Field(..., description="Статус хоста (up или down)")
    hostnames: list[str] = Field(
        default_factory=list, description="Список привязанных доменных имен хоста"
    )
    open_ports: list[NmapPortInfo] = Field(
        default_factory=list, description="Список только открытых портов"
    )
    all_ports: list[NmapPortInfo] = Field(
        default_factory=list, description="Полный список просканированных портов"
    )


class ScanAuditSummary(BaseModel):
    elapsed_time: float = Field(..., description="Время работы сканера в секундах")
    total_hosts: int = Field(..., description="Всего целей")
    up_hosts: int = Field(..., description="Активных хостов обнаружено")
    hosts: list[NmapHostReport] = Field(
        default_factory=list, description="Подробный отчет по каждому хосту"
    )
