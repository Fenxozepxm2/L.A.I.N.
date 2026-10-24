from urllib.parse import urlparse

from rich.console import Console

from pydantic_models.models import ActiveHost, IpList, ScanAuditSummary
from src.services.scan_service import SCAN

console = Console()


async def discover_hosts(ip_list: IpList) -> ActiveHost:
    """Проверяет, какие IP действительно доступны."""
    console.print("\n[bold]2. Обнаружение активных хостов[/bold]")

    scanner = SCAN()
    hosts = await scanner.check_host(ip_list)

    if not hosts:
        console.print("[yellow][!] Активных хостов не обнаружено.[/yellow]")
        return []

    console.print(f"[green][+] Активных хостов: {len(hosts)}[/green]")
    return hosts


def extract_hostname(host: str) -> str:
    """
    Очищает ввод пользователя и вытаскивает чистый hostname.
    Работает с 'http://site.com', 'https://site.com', 'site.com:443' и просто 'site.com'
    """
    host = host.strip()

    if not host.startswith(("http://", "https://")):
        parsed = urlparse(f"//{host}")
    else:
        parsed = urlparse(host)

    # Извлекаем hostname
    hostname = parsed.hostname or parsed.path

    if hostname and ":" in hostname:
        hostname = hostname.split(":")[0]

    return hostname


def result_ports(hosts: ActiveHost, 
                arguments: list | None = None, 
                preset: str | None = None
) -> ScanAuditSummary | None:
    """
    Сканирует порты/сервисы и возвращает ScanAuditSummary
    """
    from services.nmap_scan_parser import parse_nmap_results

    console.print("\n[bold]3. Сканирование портов и сервисов[/bold]")

    scanner = SCAN()
    scan_results = scanner.scan_ports(hosts, arguments, preset)

    if not scan_results:
        console.print("[yellow][!] Результатов сканирования нет.[/yellow]")
        return None

    audit_report = parse_nmap_results(scan_results)
    # print_scan_report(audit_report)
    return audit_report
