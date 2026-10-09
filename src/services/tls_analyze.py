import asyncio
from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand

async def check_ports(hostname: str, ports: list):
    scaner = Scanner()
    requests = []



    for port in ports:
        server_location = ServerNetworkLocation(hostname, port)
        scan_request = ServerScanRequest(
            server_location,
            scan_commands=[
                ScanCommand.SSL_2_0_CIPHER_SUITES, # ssl2 - полностью взломанный и запрещённый сертификат
                ScanCommand.CERTIFICATE_INFO, # данные сертификата
                ScanCommand.OPENSSL_CCS_INJECTION, # уязвимость ccs инъукции (можно провернуть man-in-the-middle)
                ScanCommand.SSL_3_0_CIPHER_SUITES, # ssl3 - уязвим к атакам poodle должен быть отключён
                ScanCommand.TLS_1_2_CIPHER_SUITES, # tls1.2 - актуальный и безопасный, но есть слабые алг. шифрования (3des, rc4)
                ScanCommand.TLS_1_0_CIPHER_SUITES, # tls1 - устаревший протокол
                ScanCommand.TLS_1_1_CIPHER_SUITES, # tls1.1 - устаревший протокол
                ScanCommand.TLS_1_3_CIPHER_SUITES, # tls1.3 - самый современный
                ScanCommand.HEARTBLEED # старая крч уязвимость, лучше проверить на всякий
            ],
        )
        
        requests.append(scan_request)
        print(f"[+] Запрос проверки создан для порта: {port}")

    print("\n[*] Запуск сканирования потенциальных TLS-портов...\n")


    scaner.queue_scans(requests)

    def get_scan_results(scanner: Scanner):
        return list(scanner.get_results())
    
    server_scan = await asyncio.to_thread(get_scan_results, scaner)

    for result in server_scan:
        # print("-"*80)
        # print(result)
        # print("-"*80)

        # if not result.scan_result:
        #     print(f"[-] Ну нету такого {result.server_location.port}")

        if result.scan_status.value == "ERROR_NO_CONNECTIVITY":
            print(f"[-] Не удалось подключиться к порту {result.server_location.port}")
            continue

        heartbleed_res = result.scan_result.heartbleed


        print("\n" + "="*80)
        print(f" .result ДЛЯ ПОРТА: {result.server_location.port}")
        print("="*80 + "\n")

        plugins = {
            "CERTIFICATE_INFO": result.scan_result.certificate_info,
            "OPENSSL_CCS_INJECTION": result.scan_result.openssl_ccs_injection,
            "SSL_2_0_CIPHER_SUITES": result.scan_result.ssl_2_0_cipher_suites,
            "SSL_3_0_CIPHER_SUITES": result.scan_result.ssl_3_0_cipher_suites,
            "TLS_1_0_CIPHER_SUITES": result.scan_result.tls_1_0_cipher_suites,
            "TLS_1_1_CIPHER_SUITES": result.scan_result.tls_1_1_cipher_suites,
            "TLS_1_2_CIPHER_SUITES": result.scan_result.tls_1_2_cipher_suites,
            "TLS_1_3_CIPHER_SUITES": result.scan_result.tls_1_3_cipher_suites,
        }

        for name, plugin_wrapper in plugins.items():
            print(f"[{name}]")
            if plugin_wrapper is None:
                print("  -> Плагин вернул None")
            elif plugin_wrapper.result is None:
                print(f"  -> Внутри .result пусто. Статус: {plugin_wrapper.status}. Ошибка: {plugin_wrapper.error_reason}")
            else:
                # Смотрим свойства НАСТОЯЩЕГО объекта с данными, который лежит в .result
                inner_fields = [attr for attr in dir(plugin_wrapper.result) if not attr.startswith("__")]
                print(f"  -> Настоящие поля внутри .result: {inner_fields}")
            print("-" * 50)



        



        # print(result.scan_result.heartbleed.status)


    

    