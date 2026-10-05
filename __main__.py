import asyncio
import json
import ipaddress
import os
import re
import sys
from urllib.parse import urlparse, urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pydantic_models.models import Target, Host, detect_target_type, ScanAuditSummary

from web_analize.http_headers import get_http_headers

from src.services.ip_service import IP_SERVICE
from src.services.scan_service import SCAN


app = typer.Typer(
    name="lain",
    help="L.A.I.N. — комплекс автоматизированного аудита безопасности",
    no_args_is_help=True,
)

console = Console()


# ============================================================
# 2. СОЗДАНИЕ TARGET
# ============================================================

def parse_target(value: str) -> Target:
    """Преобразует строку пользователя в Pydantic-модель Target."""
    value = value.strip()

    if not value:
        raise ValueError("Цель не может быть пустой.")

    return Target(value=value, type=detect_target_type(value))


# ============================================================
# 3. ПОЛУЧЕНИЕ IP-АДРЕСОВ
# ============================================================

async def resolve_target(target: Target) -> list:
    """Получает список IP-адресов из Target."""
    console.print("\n[bold]1. Определение сетевых адресов[/bold]")

    if target.type == "ip":
        ip_list = [{"ip_addres": target.value}]

    elif target.type == "cidr":
        console.print(f"[*] Обнаружена подсеть: {target.value}")
        ip_list = await IP_SERVICE.make_CIDR(target.value)

    elif target.type in ("domain", "url"):
        domain = target.value

        if target.type == "url":
            parsed = urlparse(target.value)
            if not parsed.hostname:
                raise ValueError("Не удалось извлечь домен из URL.")
            domain = parsed.hostname

        console.print(f"[*] DNS resolution: {domain}")
        ip_list = IP_SERVICE.domain_to_ip(domain)

    else:
        raise ValueError(f"Неизвестный тип цели: {target.type}")

    if not ip_list:
        raise ValueError("Не удалось получить IP-адреса.")

    console.print(f"[green][+] Получено адресов: {len(ip_list)}[/green]")
    return ip_list


# ============================================================
# 4. ОБНАРУЖЕНИЕ ЖИВЫХ ХОСТОВ
# ============================================================

async def discover_hosts(ip_list: list) -> list:
    """Проверяет, какие IP действительно доступны."""
    console.print("\n[bold]2. Обнаружение активных хостов[/bold]")

    scanner = SCAN()
    hosts = await scanner.check_host(ip_list)

    if not hosts:
        console.print("[yellow][!] Активных хостов не обнаружено.[/yellow]")
        return []

    console.print(f"[green][+] Активных хостов: {len(hosts)}[/green]")
    return hosts


# ============================================================
# 5. СКАНИРОВАНИЕ ПОРТОВ + СЕРВИСОВ
# ============================================================

def _format_service(port) -> str:
    """Компактно формирует описание сервиса из NmapPortInfo."""
    service = port.service_name or "unknown"
    software = " ".join(
        value.strip() for value in (port.product, port.version) if value
    )

    if software:
        return f"{service} ({software})"
    return service


def _print_scan_report(audit_report: ScanAuditSummary) -> None:
    """Красивый компактный вывод нормализованного ScanAuditSummary."""
    total_open = sum(len(host.open_ports) for host in audit_report.hosts)
    identified = sum(
        1
        for host in audit_report.hosts
        for port in host.open_ports
        if port.product or port.version or port.cpe
    )

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold cyan")
    summary.add_column()
    summary.add_row("Хостов", str(audit_report.total_hosts))
    summary.add_row("Активных", str(audit_report.up_hosts))
    summary.add_row("Открытых портов", str(total_open))
    summary.add_row("Идентифицированных сервисов", str(identified))
    summary.add_row("Время Nmap", f"{audit_report.elapsed_time:.2f} с")

    console.print(Panel(summary, title="Nmap", border_style="cyan"))

    for host in audit_report.hosts:
        hostname = ", ".join(host.hostnames) if host.hostnames else "без DNS"
        open_ports = sorted(port.port for port in host.open_ports)
        ports_text = ", ".join(map(str, open_ports)) if open_ports else "нет"

        console.print(
            f"\n[bold cyan]{host.ip}[/bold cyan] "
            f"[dim]({hostname})[/dim] "
            f"[green]● {host.status}[/green]"
        )
        console.print(f"  [dim]Открытые порты:[/dim] {ports_text}")

        identified_ports = [
            port
            for port in host.open_ports
            if port.product or port.version or port.cpe
        ]

        if not identified_ports:
            continue

        table = Table(box=None, padding=(0, 1), show_header=True)
        table.add_column("Порт", justify="right", style="yellow")
        table.add_column("Сервис", style="cyan")
        table.add_column("CPE", style="dim")

        for port in identified_ports:
            table.add_row(
                str(port.port),
                _format_service(port),
                port.cpe or "—",
            )

        console.print(table)


def scan_ports(hosts: list) -> ScanAuditSummary | None:
    """
    Сканирует порты/сервисы и возвращает именно ScanAuditSummary.
    Никаких сырых repr() и len(ScanAuditSummary).
    """
    from services.nmap_scan_parser import parse_nmap_results

    console.print("\n[bold]3. Сканирование портов и сервисов[/bold]")

    scanner = SCAN()
    scan_results = scanner.check_ports(hosts)

    if not scan_results:
        console.print("[yellow][!] Результатов сканирования нет.[/yellow]")
        return None

    audit_report = parse_nmap_results(scan_results)
    _print_scan_report(audit_report)
    return audit_report


# ============================================================
# 6. ПОИСК ВЕБ-СЕРВИСОВ
# ============================================================

def find_web_services(scan_results: ScanAuditSummary | None) -> list:
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

async def analyze_http(web_services: list) -> list:
    """Запускает HTTP-анализ найденных веб-сервисов параллельно."""
    if not web_services:
        return []

    console.print("\n[bold]4. Анализ HTTP/HTTPS[/bold]")

    tasks = [
        get_http_headers(ip=service["ip"], port=service["port"])
        for service in web_services
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    normalized_results = []

    for service, result in zip(web_services, results):
        if isinstance(result, Exception):
            console.print(
                f"[red][-] {service['ip']}:{service['port']}: {result}[/red]"
            )
            normalized_results.append(
                {
                    "ip": service["ip"],
                    "port": service["port"],
                    "error": str(result),
                }
            )
        else:
            normalized_results.append(
                {
                    "ip": service["ip"],
                    "port": service["port"],
                    "result": result,
                }
            )

    console.print(f"[green][+] HTTP-анализов: {len(normalized_results)}[/green]")
    return normalized_results










# ============================================================
# 9. ГЛАВНЫЙ PIPELINE
# ============================================================

async def run_audit(target: Target) -> None:
    """Полный pipeline аудита."""
    console.print(
        Panel.fit(
            "[bold cyan]L.A.I.N.[/bold cyan]\nNetwork Security Audit",
            border_style="cyan",
        )
    )
    console.print(f"\n[bold cyan]Цель:[/bold cyan] {target.value}")

    ip_list = await resolve_target(target)
    hosts = await discover_hosts(ip_list)
    if not hosts:
        return

    scan_results = scan_ports(hosts)
    if not scan_results:
        return

    web_services = find_web_services(scan_results)
    http_results = await analyze_http(web_services)

    total_open_ports = sum(
        len(host.open_ports) for host in scan_results.hosts
    )


    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Хостов", str(scan_results.total_hosts))
    summary.add_row("Активных", str(scan_results.up_hosts))
    summary.add_row("Открытых портов", str(total_open_ports))
    summary.add_row("Веб-сервисов", str(len(web_services)))
    summary.add_row("HTTP-анализов", str(len(http_results)))
    summary.add_row("Время Nmap", f"{scan_results.elapsed_time:.2f} с")

    console.print("\n")
    console.print(Panel(summary, title="Итог аудита", border_style="green"))
    console.print("[bold green]✓ Аудит завершён[/bold green]")


# ============================================================
# TYper COMMAND
# ============================================================

@app.command()
def scan(
    target: str = typer.Argument(..., help="IP, подсеть, домен или URL"),
):
    """Запустить аудит указанной цели."""
    target = target.strip()

    if not target:
        console.print("[red][!] Цель не может быть пустой.[/red]")
        raise typer.Exit(code=1)

    try:
        target_model = Target(
            value=target,
            type=detect_target_type(target),
        )
        asyncio.run(run_audit(target_model))

    except KeyboardInterrupt:
        print("\n[!] Сканирование прервано пользователем.")
    except Exception as e:
        print(f"\n[!] Непредвиденная ошибка приложения: {e}")
    finally:
        # Сброс буферов терминала (полезно для Arch Linux/STTY)
        if sys.platform != "win32":
            os.system("stty sane")
        print("\n[✓] Работа комплекса L.A.I.N. успешно завершена.")


@app.command()
def version():
    """Показать версию L.A.I.N."""
    console.print("[bold cyan]L.A.I.N.[/bold cyan] v0.1.0")


@app.command()
def help():
    console.print("[bold cyan]even a god couldnt help you[/bold cyan]")


if __name__ == "__main__":
    app()
