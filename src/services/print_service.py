    


class PRINT():

    def print_result(scan_results_list: list):
        if not scan_results_list:
            print("\033[31m[!] Нет данных для отрисовки отчета.\033[0m")
            return

        CYAN = "\033[36m"
        WHITE = "\033[37m"
        GRAY = "\033[90m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        RESET = "\033[0m"

        print(f"\n{CYAN}┌──────────────────────────────────────────────────────────────────┐")
        print(f"│       ФИНАЛЬНЫЙ ОТЧЕТ ОБ АУДИТЕ ПЕРИМЕТРА СЕТИ (L.A.I.N.)        │")
        print(f"└──────────────────────────────────────────────────────────────────┘{RESET}\n")

        for scan in scan_results_list:
            if not scan or not isinstance(scan, dict):
                continue

            scanstats = scan.get('nmap', {}).get('scanstats', {})
            elapsed_time = scanstats.get('elapsed', '0.00')

            hosts_dict = scan.get('scan', {})
            if not hosts_dict:
                continue

            for ip, host_data in hosts_dict.items():
                status_info = host_data.get('status', {})
                host_state = status_info.get('state', 'unknown')
                host_reason = status_info.get('reason', 'unknown')

                hostnames_list = host_data.get('hostnames', [])
                device_name = "не определено"
                if hostnames_list and isinstance(hostnames_list, list):
                    potential_name = hostnames_list[0].get('name', '').strip()
                    if potential_name:
                        device_name = potential_name

                os_list = host_data.get('osmatch', [])
                detected_os = "не определена"
                if os_list and isinstance(os_list, list):
                    potential_os = os_list[0].get('name', '').strip()
                    if potential_os:
                        detected_os = potential_os

                print(f"{CYAN}[*]{WHITE} Результаты аудита для хоста: {CYAN}{ip}{RESET}")
                print(f"    {GRAY}├──{RESET} Локальное имя устройства: {WHITE}{device_name}{RESET}")
                print(f"    {GRAY}├──{RESET} Операционная система:    {YELLOW}{detected_os}{RESET}")
                print(f"    {GRAY}├──{RESET} Статус сетевого узла:    {GREEN}{host_state}{RESET} ({GRAY}reason: {host_reason}{RESET})")
                print(f"    {GRAY}├──{RESET} Время анализа хоста:     {WHITE}{elapsed_time} сек.{RESET}")
                print(f"    {GRAY}└──{RESET} Состояние портов и служб:")

                tcp_ports = host_data.get('tcp', {})

                if not tcp_ports:
                    print(f"        {GRAY}└──{YELLOW} [!] В диапазоне Top-100 открытых портов не обнаружено. Хост заблокирован файрволом.{RESET}")
                    print(f"{GRAY}" + "-" * 80 + f"{RESET}\n")
                    continue

                for port, info in tcp_ports.items():
                    service_name = info.get('name', 'unknown')
                    product = info.get('product', '').strip()
                    version = info.get('version', '').strip()
                    cpe_string = info.get('cpe', '').strip()
                    extra_info = info.get('extrainfo', '').strip()

                    if product or version:
                        full_software = f"{product} {version}".strip()
                    else:
                        full_software = f"{GRAY}не определено{RESET}"

                    print(f"        {CYAN}[+]{WHITE} Порт: {CYAN}{port:<5}{WHITE} | Служба: {YELLOW}{service_name:<10}{WHITE} | ПО: {full_software}{RESET}")
                    
                    if cpe_string:
                        print(f"            {GRAY}└── CPE Идентификатор: {GREEN}{cpe_string}{RESET}")
                    
                    if extra_info:
                        print(f"            {GRAY}└── Доп. информация:   {WHITE}{extra_info}{RESET}")
                
                print(f"{GRAY}" + "-" * 80 + f"{RESET}\n")
