import asyncio

import nmap
from rich.console import Console
from tqdm.asyncio import tqdm
from middleware.pressets import SCAN_PROFILES


console = Console()


class SCAN:
    def __init__(self):

        self.np = nmap.PortScanner()

    async def scan_single_ip(self, ip: str, sem: asyncio.Semaphore) -> dict:
        args = ["-sn", "-v"]
        if ":" in ip:
            args.append("-6")
        args.append(ip)

        async with sem:
            try:
                proccer = await asyncio.create_subprocess_exec(
                    "nmap",
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, _ = await proccer.communicate()
                output = stdout.decode(encoding="utf-8", errors="ignore")
                await proccer.wait()

                if "Host is up" in output:
                    return {"ip_addres": ip, "state": "up"}
                else:
                    return {"ip_addres": ip, "state": "down"}

            except Exception:
                return None

    async def check_host(self, ip_list: list) -> list:
        """
        Проверяет статус порта "up" or "down"
        """

        CYAN = "\033[36m"
        RESET = "\033[0m"

        print(
            f"{CYAN}[*] Запуск многопоточного Host Discovery (Семафорная защита)...{RESET}"
        )
        print("[*] Лимит одновременных сокетов: 100. Пожалуйста, подождите...")

        try:
            # семафор, чтобы роутер и терминал не падали в обморок
            sem = asyncio.Semaphore(100)

            tasks = []
            for i in ip_list:
                ip = i["ip_addres"]
                task = asyncio.create_task(self.scan_single_ip(ip, sem))
                tasks.append(task)

            raw_results = []
            raw_results = await tqdm.gather(
                *tasks,
                desc="Сканирование сети",
                unit="хост",
                bar_format="{l_bar}{bar:30}{r_bar}",
            )

            up_hosts = []
            for res in raw_results:
                if res and res.get("state") == "up":
                    up_hosts.append(res)

            await asyncio.sleep(0.5)
            return up_hosts

        except Exception:
            return None

    def scan_ports(self, 
                    ip_list: list, 
                    arguments: list | None = None, 
                    preset: str | None = None
        ) -> list:
        """
            Сканирует порты и возвращает список словарей с результатом сканирования nmap
        """
        clean_preset = None
        if preset:
            clean_preset = preset.lstrip("-").lower().strip()

        try:
            result: list[dict[str, str]] = []

            user_arguments = list(arguments) if arguments else []

            for item in ip_list:
                ip = item["ip_addres"]
                
                current_arguments = []
                if clean_preset:
                    preset_args = SCAN_PROFILES.get(clean_preset, [])
                    current_arguments.extend(preset_args)

                if user_arguments:
                    # ПРОВЕРКА НА КОНФЛИКТ
                    if '-p' in user_arguments:
                        if '--top-ports' in current_arguments:
                            idx = current_arguments.index('--top-ports')
                            del current_arguments[idx:idx+2]
                        if '-F' in current_arguments:
                            current_arguments.remove('-F')
                            
                    current_arguments.extend(user_arguments)

                if not clean_preset and not user_arguments:
                    base_arguments = ['-Pn', '-sV', '-v']
                    current_arguments.extend(base_arguments)

                if ":" in ip:
                    current_arguments.append('-6')
                
                print("Финальный список аргументов перед склейкой:", current_arguments)
                
                # Склеиваем в строку для передачи в nmap
                current_arguments_str = " ".join(current_arguments)



                print(current_arguments_str)

                print(
                    f"[*] Сканирую хост {ip} (ищу открытые порты, версии ПО и ОС) С аргументами {current_arguments_str}",
                    end="",
                    flush=True,
                )
                scan = self.np.scan(hosts=ip, arguments=current_arguments_str)
                console.print("\n[green][+] Готово! [/green]")
                result.append(scan)
            return result

        except Exception as e:
            print(
                f"\n[!] Произошла ошибка во время сканирования в процессе scan_ports: {e}"
            )
