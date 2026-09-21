import socket
import nmap

import asyncio
import os
import ipaddress


# Импортируем слои приложения
from src.services.ip_service import IP_SERVICE
from src.services.scan_service import SCAN
from src.services.print_service import PRINT




# scanme.nmap.org
# 192.168.1.0/24
# main.py
import asyncio
import os
import sys




async def main():
    try:
        print("┌──[ Введите цель (IP/домен/подсеть) ]")
        target_domain = await asyncio.to_thread(input, "└──> ")
        target_domain = target_domain.strip()

        if not target_domain:
            print("[!] Цель не может быть пустой.")
            return

        # Инициализируем наш сервис сканирования (вызывается __init__)
        scanner = SCAN()

        # Определение типа цели и запуск цепочки
        if '/' in target_domain:
            ip_list = await IP_SERVICE.make_CIDR(target_domain)
        else:
            print("[*] Обработка одиночного домена/IP")
            ip_list = IP_SERVICE.domain_to_ip(target_domain)

        hosts = await scanner.check_host(ip_list)
        
        if not hosts:
            print("[!] Живых хостов в данной сети не обнаружено. Сканирование портов отменено.")
            return

        open_ports = scanner.check_ports(hosts)
        PRINT.print_result(open_ports)

    except KeyboardInterrupt:
        print("\n[!] Сканирование прервано пользователем.")
    except Exception as e:
        print(f"\n[!] Непредвиденная ошибка приложения: {e}")
    finally:
        # Сброс буферов терминала (полезно для Arch Linux/STTY)
        if sys.platform != "win32":
            os.system("stty sane")
        print("\n[✓] Работа комплекса L.A.I.N. успешно завершена.")



if __name__ == "__main__":
    asyncio.run(main())
