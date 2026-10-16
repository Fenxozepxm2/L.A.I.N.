import asyncio

from rich.console import Console
from rich.table import Table

from pydantic_models.models import (
    ScanAuditSummary,
    TargetScanInfo,
)
from src.services.print_service import PRINT
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


async def analyze_http(web_services: list) -> TargetScanInfo:
    """Запускает HTTP-анализ найденных веб-сервисов параллельно и выводит отчет."""
    if not web_services:
        return []

    tasks = [
        get_http_headers(ip=service["ip"], port=service["port"])
        for service in web_services
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    normalized_results = []

    for service, result in zip(web_services, results):
        if isinstance(result, Exception):
            item = {
                "ip": service["ip"],
                "port": service["port"],
                "error": str(result),
            }
        else:
            item = {
                "ip": service["ip"],
                "port": service["port"],
                "result": result,  # Предполагается, что тут лежит dict заголовков сервера
            }

        normalized_results.append(item)

        PRINT.print_http_result(item)

    return normalized_results
