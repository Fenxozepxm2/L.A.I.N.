import socket
import nmap

import asyncio
import os
import ipaddress



# Импортируем слои приложения
from src.services.ip_service import IP_SERVICE
from src.services.scan_service import SCAN
from src.services.print_service import PRINT
from src.web_analize.http_headers import get_http_headers




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
        live_ports = PRINT.print_result(open_ports)

        web_services = []
        
        # Перебираем порт и его данные (port_info)
        for port, port_info in live_ports.items():
            # Проверяем, что порт открыт и его служба связана с вебом (http или https)
            if port_info.get('state') == 'open':
                service_name = port_info.get('name', '').lower()
                
                if 'http' in service_name or 'https' in service_name:
                    # (В будущем, если хостов много, ip нужно будет передавать вместе с live_ports)
                    current_ip = hosts[0]['ip_addres'] 
                    web_services.append({'ip': current_ip, 'port': port})

        if web_services:
            print(f"\n[+] Обнаружено веб-служб для анализа: {len(web_services)}")
            
            # Асинхронный запрос согласия пользователя
            answr = await asyncio.to_thread(
                input, f"└──> Хотите начать асинхронный анализ HTTP-заголовков {target_domain}({current_ip})? [Y/n]: "
            )
            answr = answr.lower().strip()
            
            if answr in ['y', '']:
                print("\n[*] Запуск параллельного анализа HTTP-заголовков...")
                
                # Собираем пачку асинхронных задач
                tasks = []
                for service in web_services:
                    # Формируем задачу для httpx (убедись, что http_headers_analyzer — это async def)
                    task = get_http_headers(ip=service['ip'], port=service['port'])
                    tasks.append(task)
                
                # Стреляем всеми запросами ОДНОВРЕМЕННО
                await asyncio.gather(*tasks)
                print("\n[+] Анализ HTTP-заголовков успешно завершен.")
            else:
                print("[*] Анализ заголовков пропущен пользователем.")

            

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
