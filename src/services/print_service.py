from pydantic_models.models import AllTlsScanResult, ScanAuditSummary


class PRINT:
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

    def print_result(scan_results_list: list) -> dict:
        if not scan_results_list:
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

        for scan in scan_results_list:
            if not scan or not isinstance(scan, dict):
                continue

            scanstats = scan.get("nmap", {}).get("scanstats", {})
            elapsed_time = scanstats.get("elapsed", "0.00")

            hosts_dict = scan.get("scan", {})
            if not hosts_dict:
                continue

            for ip, host_data in hosts_dict.items():
                status_info = host_data.get("status", {})
                host_state = status_info.get("state", "unknown")
                host_reason = status_info.get("reason", "unknown")

                hostnames_list = host_data.get("hostnames", [])
                device_name = "не определено"
                if hostnames_list and isinstance(hostnames_list, list):
                    potential_name = hostnames_list[0].get("name", "").strip()
                    if potential_name:
                        device_name = potential_name

                os_list = host_data.get("osmatch", [])
                detected_os = "не определена"
                if os_list and isinstance(os_list, list):
                    potential_os = os_list[0].get("name", "").strip()
                    if potential_os:
                        detected_os = potential_os

                print(
                    f"{CYAN}[*]{WHITE} Результаты аудита для хоста: {CYAN}{ip}{RESET}"
                )
                print(
                    f"    {GRAY}├──{RESET} Локальное имя устройства: {WHITE}{device_name}{RESET}"
                )
                print(
                    f"    {GRAY}├──{RESET} Операционная система:    {YELLOW}{detected_os}{RESET}"
                )
                print(
                    f"    {GRAY}├──{RESET} Статус сетевого узла:    {GREEN}{host_state}{RESET} ({GRAY}reason: {host_reason}{RESET})"
                )
                print(
                    f"    {GRAY}├──{RESET} Время анализа хоста:     {WHITE}{elapsed_time} сек.{RESET}"
                )
                print(f"    {GRAY}└──{RESET} Состояние портов и служб:")

                tcp_ports = host_data.get("tcp", {})

                if not tcp_ports:
                    print(
                        f"        {GRAY}└──{YELLOW} [!] В диапазоне Top-100 открытых портов не обнаружено. Хост заблокирован файрволом.{RESET}"
                    )
                    print(f"{GRAY}" + "-" * 80 + f"{RESET}\n")
                    continue

                for port, info in tcp_ports.items():
                    service_name = info.get("name", "unknown")
                    product = info.get("product", "").strip()
                    version = info.get("version", "").strip()
                    cpe_string = info.get("cpe", "").strip()
                    extra_info = info.get("extrainfo", "").strip()

                    if product or version:
                        full_software = f"{product} {version}".strip()
                    else:
                        full_software = f"{GRAY}не определено{RESET}"

                    print(
                        f"        {CYAN}[+]{WHITE} Порт: {CYAN}{port:<5}{WHITE} | Служба: {YELLOW}{service_name:<10}{WHITE} | ПО: {full_software}{RESET}"
                    )

                    if cpe_string:
                        print(
                            f"            {GRAY}└── CPE Идентификатор: {GREEN}{cpe_string}{RESET}"
                        )

                    if extra_info:
                        print(
                            f"            {GRAY}└── Доп. информация:   {WHITE}{extra_info}{RESET}"
                        )

                return tcp_ports

    @staticmethod
    def print_http_result(http_result: dict) -> None:
        if not http_result:
            print("\033[31m[!] Нет данных для отрисовки HTTP-отчета.\033[0m")
            return

        CYAN = "\033[36m"
        WHITE = "\033[37m"
        GRAY = "\033[90m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        RED = "\033[31m"
        RESET = "\033[0m"

        ip = http_result.get("ip")
        port = http_result.get("port")

        print(
            f"{CYAN}[*]{WHITE} Результаты HTTP-аудита для адреса: {CYAN}{ip}:{port}{RESET}"
        )

        # Если во время запроса произошла ошибка (таймаут, отказ в соединении и т.д.)
        if "error" in http_result:
            print(
                f"    {GRAY}└──{RESET} {RED}[!] Ошибка сканирования HTTP: {http_result['error']}{RESET}"
            )
            print(f"{GRAY}" + "-" * 80 + f"{RESET}\n")
            return

        headers_data = http_result.get("result", {})
        if not headers_data:
            print(
                f"    {GRAY}└──{RESET} {YELLOW}[!] Сервер вернул пустой ответ.{RESET}"
            )
            print(f"{GRAY}" + "-" * 80 + f"{RESET}\n")
            return

        # --- БЛОК 1: Основная информация о веб-сервере ---
        server_software = headers_data.get("Server", f"{GRAY}не определено{RESET}")
        content_type = headers_data.get("Content-Type", f"{GRAY}не определено{RESET}")

        print(f"    {GRAY}├──{RESET} Инвентаризация веб-службы:")
        print(
            f"    {GRAY}│   ├──{RESET} Веб-сервер (ПО):       {YELLOW}{server_software}{RESET}"
        )
        print(
            f"    {GRAY}│   └──{RESET} Тип контента:          {WHITE}{content_type}{RESET}"
        )

        # --- БЛОК 2: Анализ заголовков безопасности (Security Headers Audit) ---
        print(f"    {GRAY}├──{RESET} Аудит заголовков безопасности (Compliance):")

        # Список критических заголовков защиты и их описание для диплома
        security_headers = {
            "Strict-Transport-Security": "Защита от снижения шифрования (HSTS)",
            "Content-Security-Policy": "Защита от XSS и инъекций контента (CSP)",
            "X-Frame-Options": "Защита от UI-redirection (Clickjacking)",
            "X-Content-Type-Options": "Защита от MIME-sniffing атак",
            "X-XSS-Protection": "Устаревший фильтр XSS (Рекомендуется CSP)",
        }

        missing_headers = []

        for header_name, description in security_headers.items():
            # Ищем заголовок без учета регистра (HTTP-заголовки регистронезависимы)
            header_value = next(
                (
                    v
                    for k, v in headers_data.items()
                    if k.lower() == header_name.lower()
                ),
                None,
            )

            if header_value:
                # Ограничиваем длину вывода значения, чтобы не ломать терминал
                short_value = (
                    header_value
                    if len(header_value) < 45
                    else f"{header_value[:42]}..."
                )
                print(
                    f"    {GRAY}│   ├──{RESET} {GREEN}[+] {header_name:<26}{RESET} ── {WHITE}{short_value}{RESET}"
                )
            else:
                missing_headers.append(header_name)
                print(
                    f"    {GRAY}│   ├──{RESET} {RED}[-] {header_name:<26}{RESET} ── {GRAY}ОТСУТСТВУЕТ ({description}){RESET}"
                )

        # Выводим резюме по безопасности
        if not missing_headers:
            print(
                f"    {GRAY}│   └──{RESET} Статус безопасности:   {GREEN}ОТЛИЧНО (Все базовые заголовки настроены){RESET}"
            )
        elif len(missing_headers) <= 2:
            print(
                f"    {GRAY}│   └──{RESET} Статус безопасности:   {YELLOW}СРЕДНИЙ (Пропущены некоторые настройки){RESET}"
            )
        else:
            print(
                f"    {GRAY}│   └──{RESET} Статус безопасности:   {RED}НИЗКИЙ (Рекомендуется ужесточение конфигурации){RESET}"
            )

        # --- БЛОК 3: Сырой вывод для отладки ---
        print(f"    {GRAY}└──{RESET} Полный дамп полученных HTTP-заголовков:")

        headers_items = list(headers_data.items())
        for idx, (key, val) in enumerate(headers_items):
            is_last = idx == len(headers_items) - 1
            branch = "└──" if is_last else "├──"
            print(
                f"        {GRAY}{branch}{RESET} {CYAN}{key}{RESET}: {WHITE}{val}{RESET}"
            )

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
