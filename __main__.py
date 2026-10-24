import asyncio
import os
import sys
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel

from pydantic_models.models import (
    Target,
    detect_target_type,
)
from services.tls_analyze import check_tls_ports
from src.middleware.hosts import discover_hosts, extract_hostname, result_ports
from src.middleware.target import parse_target, resolve_target
from src.services.print_service import PRINT
from src.web_analize.http_service import analyze_http, find_web_services

app = typer.Typer(
    name="lain",
    help="L.A.I.N. — комплекс автоматизированного аудита безопасности",
    no_args_is_help=True,
)

console = Console()


# nmap.scanme.org
# 192.168.1.0/24
# badssl.com (tls)


# ГЛАВНЫЙ PIPELINE


async def run_audit(
    target: Target,
    flags: list | None = None,
    preset: str | None = None
) -> None:
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

    scan_results = result_ports(hosts, flags, preset)
    if not scan_results:
        return

    PRINT.print_ports_info(scan_results)

    web_services = find_web_services(scan_results)

    http_results = await analyze_http(web_services)

    for http_result in http_results:
        PRINT.print_http_result(http_result)


# ============================================================
# Typer COMMAND
# ============================================================


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True}
)
def scan(
    target: Annotated[str, typer.Argument(help="IP, подсеть, домен или URL")],
    
    preset: Annotated[str, typer.Argument(help="пресеты для сканирования, от тихого до агрессивного")] = None,
    
    custom_flags: Annotated[list[str], typer.Argument(help="Кастомные флаги для сканирования")] = None,

):
    """ "
    запуск полноценного полного аудита (через конфиг)
    """

    target = target.strip()

    if not target:
        console.print("[red][!] Цель не может быть пустой.[/red]")
        raise typer.Exit(code=1)

    try:
        target_model = Target(
            value=target,
            type=detect_target_type(target),
        )

        print(target)
        print(preset)

        print(custom_flags)

        asyncio.run(run_audit(target_model, custom_flags, preset))
            


    except KeyboardInterrupt:
        print("\n[!] Сканирование прервано пользователем.")
    except Exception:
        print("\n[!] Непредвиденная ошибка приложения:")
        console.print_exception()
    finally:
        # Сброс буферов терминала (полезно для Arch Linux/STTY)
        if sys.platform != "win32":
            os.system("stty sane")
        print("\n[✓] Работа комплекса L.A.I.N. успешно завершена.")


@app.command()
def audit(
    target: Annotated[str, typer.Argument(..., help="IP, подсеть, домен или URL")] = "",
):
    """
    Запуск скана таргета (без tls, http)
    """


@app.command()
def tls(
    hostname: Annotated[str, typer.Argument(..., help="ip/hostname")] = "",
    ports: Annotated[list[int], typer.Argument(..., help="ports")] = [],
) -> None:

    hostname = extract_hostname(hostname)

    print(f"{hostname}: " + f"{ports}")

    asyncio.run(check_tls_ports(hostname, ports))


@app.command()
def target(
    hostname: Annotated[str, typer.Argument(..., help="ip/hostname")] = "",
) -> None:

    target = parse_target(hostname)

    wtf = asyncio.run(resolve_target(target))

    print(f"{wtf}")


@app.command()
def version():
    """Показать версию L.A.I.N."""
    console.print("[bold cyan]L.A.I.N.[/bold cyan] v0.4.0")


@app.command()
def help():
    console.print("[bold cyan]even a god couldnt help you[/bold cyan]")


if __name__ == "__main__":
    app()