from urllib.parse import urlparse

from rich.console import Console

from pydantic_models.models import IpList, Target, detect_target_type
from src.services.ip_service import IP_SERVICE

console = Console()


def parse_target(value: str | Target) -> Target:
    """Преобразует строку пользователя в Pydantic-модель Target."""
    value = value.strip()

    if not value:
        raise ValueError("Цель не может быть пустой.")

    print(Target(value=value, type=detect_target_type(value)))

    return Target(value=value, type=detect_target_type(value))


async def resolve_target(target: Target) -> IpList:
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
