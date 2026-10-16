import asyncio

from rich.console import Console
from rich.table import Table

from pydantic_models.models import (
    ScanAuditSummary,
    TargetScanInfo,
    WebService,
)
from web_analize.http_headers import get_http_headers

console = Console()


def find_web_services(scan_results: ScanAuditSummary | None) -> list[dict[str, str]]:
    """Из нормализированного отчёта выбирает HTTP/HTTPS-сервисы."""
    if not scan_results:
        return []

    web_services = []

    for host in scan_results.hosts:
        for port in host.open_ports:
            service_name = (port.service_name or "").lower()

            if "http" in service_name or port.port in (80, 443, 8080, 8443):
                web_services.append(
                    {
                        "ip": host.ip,
                        "port": port.port,
                        "service": service_name or "http",
                    }
                )

    if web_services:
        table = Table(title="HTTP / HTTPS", box=None)
        table.add_column("Хост")
        table.add_column("Порт", justify="right")
        table.add_column("Сервис")

        for item in web_services:
            table.add_row(
                item["ip"],
                str(item["port"]),
                item["service"],
            )

        console.print(table)
    else:
        console.print("[yellow][*] Веб-сервисы не обнаружены.[/yellow]")

    return web_services


# ============================================================
# 7. HTTP АНАЛИЗ
# ============================================================


HTTPS_PORTS = {443, 8443}


async def analyze_http(web_services: list[WebService | dict]) -> list[TargetScanInfo]:
    """Параллельный HTTP-анализ найденных веб-сервисов. Ничего не печатает."""
    if not web_services:
        return []

    # model_validate принимает и WebService, и обычный dict
    services = [WebService.model_validate(s) for s in web_services]

    probes = await asyncio.gather(
        *(get_http_headers(ip=s.ip, port=s.port) for s in services),
        return_exceptions=True,
    )

    results: list[TargetScanInfo] = []
    for service, probe in zip(services, probes):
        scheme = "https" if service.port in HTTPS_PORTS else "http"

        if isinstance(probe, BaseException):
            results.append(
                TargetScanInfo(
                    ip=service.ip,
                    port=service.port,
                    scheme=scheme,
                    error=str(probe) or type(probe).__name__,
                )
            )
        else:
            results.append(
                TargetScanInfo(
                    ip=service.ip,
                    port=service.port,
                    scheme=scheme,
                    headers=probe.headers,
                    result=probe.findings,
                )
            )

    return results
