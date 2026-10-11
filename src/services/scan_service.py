import ipaddress
import asyncio
import nmap
from tqdm.asyncio import tqdm



class SCAN():


    def __init__(self):

        self.np = nmap.PortScanner()


    async def scan_single_ip(self, ip: str, sem: asyncio.Semaphore) -> dict:
        args = ['-sn', '-v', '-PS80,443']
        if ':' in ip:
            args.append('-6')
        args.append(ip)

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


    async def check_host(self, ip_list: list) -> list:
        """
        Проверяет статус порта "up" or "down"
        """


        CYAN = "\033[36m"
        RESET = "\033[0m"
        
        print(f"{CYAN}[*] Запуск многопоточного Host Discovery (Семафорная защита)...{RESET}")
        print(f"[*] Лимит одновременных сокетов: 100. Пожалуйста, подождите...")

        try:
            # семафор, чтобы роутер и терминал не падали в обморок
            sem = asyncio.Semaphore(100)
            
            tasks = []
            for i in ip_list:
                ip = i['ip_addres']
                task = asyncio.create_task(self.scan_single_ip(ip, sem))
                tasks.append(task)

            raw_results = []
            raw_results = await tqdm.gather(*tasks, desc="Сканирование сети", unit="хост", bar_format="{l_bar}{bar:30}{r_bar}")

            up_hosts = []
            for res in raw_results:
                if res and res.get('state') == 'up':
                    up_hosts.append(res)

            await asyncio.sleep(0.5)
            print(up_hosts)
            return up_hosts

        except Exception:
            return None


    def check_ports(self, ip_list: list) -> list:
        """
        Без пинга ищет открытые порты, версии ПО, с флагом скорости 
        (если хочется быстро то -T4, но при нём не всегда вытаскивается cve, лучше использовать -T3 будет дольше, но достанет точно)
        """


        try:
            result: list[dict[str, str]] = []
            for item in ip_list:
                ip = item['ip_addres']
                base_arg = '-Pn -sV -v -F -T4' # 
                if ':' in ip:
                    base_arg += ' -6'

                print(f"[*] Сканирую хост {ip} (ищу открытые порты, версии ПО и ОС) С аргументами {base_arg}", end="", flush=True)
                scan = self.np.scan(hosts=ip, arguments=base_arg)
                print("Готово! " + '\n')
                result.append(scan)
            return result
                
        except Exception as e:
            print(f"\n[!] Произошла ошибка во время сканирования в процессе check_ports: {e}")