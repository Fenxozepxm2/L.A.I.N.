from pydantic_models.models import (
    SECURITY_HEADERS,
    AllTlsScanResult,
    ScanAuditSummary,
    TargetScanInfo,
)


class PRINT:
    @staticmethod
    def print_ports_info(audit_report: ScanAuditSummary) -> None:
        """Подробный древовидный вывод нормализованного ScanAuditSummary."""
        if not audit_report or not audit_report.hosts:
            print("\033[31m[!] Нет данных для отрисовки отчета.\033[0m")
            return

        CYAN = "\033[36m"
        WHITE = "\033[37m"
        GRAY = "\033[90m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        RESET = "\033[0m"

        print(
            f"\n{CYAN}┌──────────────────────────────────────────────────────────────────┐"
        )
        print("│       ФИНАЛЬНЫЙ ОТЧЕТ ОБ АУДИТЕ ПЕРИМЕТРА СЕТИ (L.A.I.N.)        │")
        print(
            f"└──────────────────────────────────────────────────────────────────┘{RESET}\n"
        )

        elapsed_time = f"{audit_report.elapsed_time:.2f}"

        for host in audit_report.hosts:
            device_name = (
                ", ".join(host.hostnames) if host.hostnames else "не определено"
            )

            print(
                f"{CYAN}[*]{WHITE} Результаты аудита для хоста: {CYAN}{host.ip}{RESET}"
            )
            print(
                f"    {GRAY}├──{RESET} Локальное имя устройства: {WHITE}{device_name}{RESET}"
            )
            print(
                f"    {GRAY}├──{RESET} Статус сетевого узла:    {GREEN}{host.status}{RESET}"
            )
            print(
                f"    {GRAY}├──{RESET} Время анализа:           {WHITE}{elapsed_time} сек.{RESET}"
            )
            print(f"    {GRAY}└──{RESET} Состояние портов и служб:")

            if not host.open_ports:
                print(
                    f"        {GRAY}└──{YELLOW} [!] В диапазоне Top-100 открытых портов не обнаружено. "
                    f"Хост заблокирован файрволом.{RESET}"
                )
                print(f"{GRAY}" + "-" * 80 + f"{RESET}\n")
                continue

            for port_info in sorted(host.open_ports, key=lambda p: p.port):
                product = (port_info.product or "").strip()
                version = (port_info.version or "").strip()
                cpe_string = (port_info.cpe or "").strip()
                extra_info = (port_info.extrainfo or "").strip()

                if product or version:
                    full_software = f"{product} {version}".strip()
                else:
                    full_software = f"{GRAY}не определено{RESET}"

                print(
                    f"        {CYAN}[+]{WHITE} Порт: {CYAN}{port_info.port:<5}{WHITE} "
                    f"| Служба: {YELLOW}{port_info.service_name:<10}{WHITE} "
                    f"| ПО: {full_software}{RESET}"
                )

                if cpe_string:
                    print(
                        f"            {GRAY}└── CPE Идентификатор: {GREEN}{cpe_string}{RESET}"
                    )

                if extra_info:
                    print(
                        f"            {GRAY}└── Доп. информация:   {WHITE}{extra_info}{RESET}"
                    )

            print(f"{GRAY}" + "-" * 80 + f"{RESET}\n")

    @staticmethod
    def print_http_result(info: TargetScanInfo) -> None:
        if info is None:
            print("\033[31m[!] Нет данных для отрисовки HTTP-отчета.\033[0m")
            return

        CYAN = "\033[36m"
        WHITE = "\033[37m"
        GRAY = "\033[90m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        RED = "\033[31m"
        RESET = "\033[0m"

        print(
            f"{CYAN}[*]{WHITE} Результаты HTTP-аудита для адреса: "
            f"{CYAN}{info.scheme}://{info.ip}:{info.port}{RESET}"
        )

        if info.error:
            print(
                f"    {GRAY}└──{RESET} {RED}[!] Ошибка сканирования HTTP: {info.error}{RESET}"
            )
            print(f"{GRAY}" + "-" * 80 + f"{RESET}\n")
            return

        if not info.headers:
            print(
                f"    {GRAY}└──{RESET} {YELLOW}[!] Сервер не вернул HTTP-заголовки.{RESET}"
            )
            print(f"{GRAY}" + "-" * 80 + f"{RESET}\n")
            return

        # --- БЛОК 1: Инвентаризация ---
        na = f"{GRAY}не определено{RESET}"
        server_software = info.header("Server") or na
        content_type = info.header("Content-Type") or na

        print(f"    {GRAY}├──{RESET} Инвентаризация веб-службы:")
        print(
            f"    {GRAY}│   ├──{RESET} Веб-сервер (ПО):       {YELLOW}{server_software}{RESET}"
        )
        print(
            f"    {GRAY}│   └──{RESET} Тип контента:          {WHITE}{content_type}{RESET}"
        )

        # --- БЛОК 2: Заголовки безопасности ---
        print(f"    {GRAY}├──{RESET} Аудит заголовков безопасности:")

        applicable = info.applicable_security_headers()
        missing = info.missing_security_headers()

        for header_name, description in SECURITY_HEADERS.items():
            if header_name not in applicable:
                print(
                    f"    {GRAY}│   ├──{RESET} {GRAY}[~] {header_name:<26}{RESET} ── "
                    f"{GRAY}не применимо (проверяется только по HTTPS){RESET}"
                )
            elif header_name in missing:
                print(
                    f"    {GRAY}│   ├──{RESET} {RED}[-] {header_name:<26}{RESET} ── "
                    f"{GRAY}ОТСУТСТВУЕТ ({description}){RESET}"
                )
            else:
                value = info.header(header_name) or ""
                short_value = value if len(value) < 45 else f"{value[:42]}..."
                print(
                    f"    {GRAY}│   ├──{RESET} {GREEN}[+] {header_name:<26}{RESET} ── {WHITE}{short_value}{RESET}"
                )

        if not missing:
            print(
                f"    {GRAY}│   └──{RESET} Статус безопасности:   {GREEN}ОТЛИЧНО (Все базовые заголовки настроены){RESET}"
            )
        elif len(missing) <= 2:
            print(
                f"    {GRAY}│   └──{RESET} Статус безопасности:   {YELLOW}СРЕДНИЙ (Пропущены некоторые настройки){RESET}"
            )
        else:
            print(
                f"    {GRAY}│   └──{RESET} Статус безопасности:   {RED}НИЗКИЙ (Рекомендуется ужесточение конфигурации){RESET}"
            )

        # --- БЛОК 3: Замечания анализа ---
        issues = info.result.issues(info.is_https) if info.result else {}
        if issues:
            print(f"    {GRAY}├──{RESET} Выявленные замечания:")
            items = list(issues.items())
            for idx, (title, text) in enumerate(items):
                branch = "└──" if idx == len(items) - 1 else "├──"
                print(
                    f"    {GRAY}│   {branch}{RESET} {CYAN}{title}{RESET}: {YELLOW}{text}{RESET}"
                )

        # --- БЛОК 4: Сырые заголовки ---
        print(f"    {GRAY}└──{RESET} Полученные HTTP-заголовки:")

        headers_items = list(info.headers.items())
        for idx, (key, val) in enumerate(headers_items):
            branch = "└──" if idx == len(headers_items) - 1 else "├──"
            print(
                f"        {GRAY}{branch}{RESET} {CYAN}{key}{RESET}: {WHITE}{val}{RESET}"
            )

        print(f"{GRAY}" + "-" * 80 + f"{RESET}\n")

    @staticmethod
    def print_tls_result(tls_results: AllTlsScanResult) -> None:
        if not tls_results:
            print("\033[31m[!] Нет данных для отрисовки TLS-отчета.\033[0m")
            return

        CYAN = "\033[36m"
        WHITE = "\033[37m"
        GRAY = "\033[90m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        RED = "\033[31m"
        RESET = "\033[0m"

        print(
            f"{CYAN}[*]{WHITE} Результаты TLS-аудита для хоста: {CYAN}{tls_results.target_host}{RESET}"
        )

        # --- БЛОК СЕРТИФИКАТА ---
        cert = tls_results.certificate
        if cert:
            cert_status = (
                f"{GREEN}Валиден{RESET}" if cert.is_valid else f"{RED}НЕВАЛИДЕН{RESET}"
            )
            print(f"    {GRAY}├──{RESET} Данные SSL/TLS-сертификата:")
            print(
                f"    {GRAY}│   ├──{RESET} Субъект (CN):          {WHITE}{cert.subject}{RESET}"
            )
            print(
                f"    {GRAY}│   ├──{RESET} Издатель (Issuer):     {WHITE}{cert.issuer}{RESET}"
            )
            print(f"    {GRAY}│   ├──{RESET} Статус сертификата:   {cert_status}")

            # Подсветка слабых ключей
            key_color = GREEN if cert.key_size >= 2048 else RED
            print(
                f"    {GRAY}│   ├──{RESET} Алгоритм и ключ:       {YELLOW}{cert.key_type}{RESET} ({key_color}{cert.key_size} бит{RESET})"
            )
            print(
                f"    {GRAY}│   ├──{RESET} Отпечаток SHA-256:     {GRAY}{cert.fingerprint_sha256}{RESET}"
            )
            print(
                f"    {GRAY}│   └──{RESET} Срок действия:         {GRAY}{cert.not_before}{RESET} ── {GRAY}{cert.not_after}{RESET}"
            )

            if cert.validation_errors:
                print(
                    f"    {GRAY}│       └── {RED}[!] Ошибки валидации: {cert.validation_errors}{RESET}"
                )
        else:
            print(
                f"    {GRAY}├──{RESET} Данные SSL/TLS-сертификата: {RED}отсутствуют или не получены{RESET}"
            )

        # --- БЛОК ПРОТОКОЛОВ И ШИФРОВ ---
        print(f"    {GRAY}└──{RESET} Поддерживаемые протоколы и наборы шифров:")

        ciphers_list = tls_results.ciphers
        if not ciphers_list:
            print(
                f"        {GRAY}└──{YELLOW} [!] Ни один протокол шифрования не принят сервером.{RESET}"
            )
            print(f"{GRAY}" + "-" * 80 + f"{RESET}\n")
            return

        for idx, tls_version in enumerate(ciphers_list):
            # Проверяем последний ли элемент в списке версий для красивого закрытия ветки └──
            is_last_version = idx == len(ciphers_list) - 1
            ver_branch = "└──" if is_last_version else "├──"
            ver_prefix = "   " if is_last_version else "│  "

            # Цветовая индикация опасности старых протоколов
            if tls_version.version in ["tls_1_0", "tls_1_1"]:
                version_status = (
                    f"{RED}{tls_version.version.upper()} (УСТАРЕЛ/ОПАСЕН){RESET}"
                )
            elif tls_version.version == "tls_1_2":
                version_status = f"{GREEN}{tls_version.version.upper()}{RESET}"
            elif tls_version.version == "tls_1_3":
                version_status = (
                    f"{CYAN}{tls_version.version.upper()} (РЕКОМЕНДУЕТСЯ){RESET}"
                )
            else:
                version_status = f"{WHITE}{tls_version.version.upper()}{RESET}"

            print(f"        {GRAY}{ver_branch}{RESET} Протокол {version_status}:")

            if not tls_version.accepted_ciphers:
                print(
                    f"        {GRAY}{ver_prefix}   └──{GRAY} [на порту не поддерживается]{RESET}"
                )
                continue

            for c_idx, cipher_name in enumerate(tls_version.accepted_ciphers):
                is_last_cipher = c_idx == len(tls_version.accepted_ciphers) - 1
                cipher_branch = "└──" if is_last_cipher else "├──"

                # Подсвечиваем заведомо дырявые шифры (например, старый 3DES, RC4 или NULL)
                if any(bad in cipher_name for bad in ["3DES", "RC4", "NULL", "ANON"]):
                    cipher_status = f"{RED}{cipher_name:<40} [УЯЗВИМ]{RESET}"
                # Подсвечиваем шифры без Perfect Forward Secrecy (начинаются просто с TLS_RSA_)
                elif cipher_name.startswith("TLS_RSA_"):
                    cipher_status = f"{YELLOW}{cipher_name:<40} [Без PFS]{RESET}"
                else:
                    cipher_status = f"{WHITE}{cipher_name}{RESET}"

                print(
                    f"        {GRAY}{ver_prefix}   {cipher_branch}{RESET} {cipher_status}"
                )
