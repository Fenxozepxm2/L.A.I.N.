import socket
import nmap
from tqdm.asyncio import tqdm
import asyncio
import os
import ipaddress


np = nmap.PortScanner()

def domain_to_ip(domain: str) -> list:
    """
    Возвращает список словарей
    [   {'ip_addres': str,
        'ip_version': str,
        'real_name': str
        },

        {'ip_addres': str,
        'ip_version': str,
        'real_name': str
        }
    ] 
    
    всех полученных IPv4 && IPv6
    """

    info_ip = socket.getaddrinfo(host=domain, port=0, family=socket.AF_UNSPEC, flags=socket.AI_CANONNAME, type=socket.SOCK_STREAM)
    scan_result = []
    for item in info_ip:
        family, socktype, proto, canonname, addr = item
        IPv = "IPv6" if family == socket.AF_INET6 else "IPv4"
        if canonname == '':
            canonname = domain
        result = {
            "ip_addres": addr[0],
            "ip_version": IPv,
            "real_name": canonname
        }
        scan_result.append(result)
    print(scan_result)
    return scan_result
        

# МОДЕРНИЗАЦИЯ: Добавили параметр sem (семафор)
async def scan_single_ip(ip: str, sem: asyncio.Semaphore) -> dict:
    args = ['-sn', '-v']
    if ':' in ip:
        args.append('-6')
    args.append(ip)

    # async with гарантирует, что одновременно в этой точке будет находиться не больше N хостов
    async with sem:
        try:
            proccer = await asyncio.create_subprocess_exec(
                'nmap', *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, _ = await proccer.communicate()
            output = stdout.decode(encoding='utf-8', errors='ignore')
            await proccer.wait()

            if "Host is up" in output:
                return {'ip_addres': ip, 'state': 'up'}
            else:
                return {'ip_addres': ip, 'state': 'down'}

        except Exception:
            return None


# МОДЕРНИЗАЦИЯ: Логика распределения задач и правильный плавный tqdm
async def check_host(ip_list: list) -> list:
    CYAN = "\033[36m"
    RESET = "\033[0m"
    
    print(f"{CYAN}[*] Запуск многопоточного Host Discovery (Семафорная защита)...{RESET}")
    print(f"[*] Лимит одновременных сокетов: 100. Пожалуйста, подождите...")

    try:
        # Создаем семафор. 30 — идеальное число, чтобы роутер и терминал не падали в обморок
        sem = asyncio.Semaphore(100)
        
        # Переносим tqdm на этап сбора результатов, чтобы полоска двигалась ЧЕСТНО и плавно!
        tasks = []
        for i in ip_list:
            ip = i['ip_addres']
            # Передаем семафор внутрь каждой подзадачи
            task = asyncio.create_task(scan_single_ip(ip, sem))
            tasks.append(task)

        # Красивый асинхронный сборщик с живой полосой загрузки
        raw_results = []
        # tqdm.gather — специальный макрос библиотеки, который сам двигает полоску по мере готовности задач
        raw_results = await tqdm.gather(*tasks, desc="Сканирование сети", unit="хост", bar_format="{l_bar}{bar:30}{r_bar}")

        up_hosts = []
        for res in raw_results:
            if res and res.get('state') == 'up':
                up_hosts.append(res)

        # Даем терминалу Arch Linux полсекунды сбросить буферы вывода
        await asyncio.sleep(0.5)
        print(up_hosts)
        return up_hosts

    except Exception:
        return None

    
def check_ports(ip_list: list):
    try:
        for item in ip_list:
            ip = item['ip_addres']
            base_arg = '-F -sV -T4 -Pn'
            if ':' in ip:
                base_arg += ' -6'

            print(f"[*] Сканирую хост {ip} (ищу открытые порты и версии ПО)... ", end="", flush=True)
            scan = np.scan(hosts=ip, arguments=base_arg)
            print("Готово! " + '\n')
            print("-" * 100)
            print(scan)
            print("-" * 100)
            
    except Exception as e:
        print(f"\n[!] Произошла ошибка во время сканирования в процессе check_ports: {e}")



async def scan_CIDR(ip: str):
    net = ipaddress.ip_network(ip, strict=False)
    
    all_ips = []
    
    for single_ip in net.hosts():  # .hosts() сразу откидывает служебные .0 и .255
        all_ips.append({'ip_addres': str(single_ip)})
        
        if len(all_ips) >= 256:
            break
            
    return all_ips

        



# scanme.nmap.org
# 192.168.1.0/24

async def main():
    try:
        # Добавляем явное приглашение к вводу, чтобы не смотреть в пустой экран!
        print("┌──[ Введите цель (IP/домен/подсеть) ]")
        target_domain = str(input("└──> ").strip())

        if '/' in target_domain:
            ip_list = await scan_CIDR(target_domain)
            hosts = await check_host(ip_list)
            open_ports = check_ports(hosts)
        else:
            print("[*] Обработка одиночного домена/IP")
            ip_list = domain_to_ip(target_domain)
            hosts = await check_host(ip_list)
            open_ports = check_ports(hosts)



    finally:
        os.system("stty sane")
        print("\n[✓] Работа комплекса завершена.")




if __name__ == "__main__":
    asyncio.run(main())
