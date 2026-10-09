import asyncio
from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand, ServerScanResult
from datetime import datetime

async def check_tls_ports(hostname: str, ports: list):
    scaner = Scanner()
    requests = []

    current_time = datetime.now()

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

        accepted = await parse_sertifacates(result)
        # смотрим что ваще пришло нам в скане
        print(accepted)
        # пишем ещё анализ http заголовков 

        
            

    


async def parse_sertifacates(result: ServerScanResult, tls_version: list[str] = None) -> dict[str, list[str]]: # пока что лист чуть позже добавь модель (по настроению)
    
    """
        Универсально парсит принятые чипсет suit с tls 
    """
    
    if not tls_version:
        # это приставки от _cipher_suites
        tls_version = ["tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"]
    
    all_accepted_suits = {}

    for version in tls_version:
        full_name_tls_version = f"{version}_cipher_suites"

        tls_data = getattr(result.scan_result, full_name_tls_version, None)

        if not tls_data:
            continue

        if tls_data.status.value == "COMPLETED":
            accepted_suite_list = []

            for accepted_suite in tls_data.result.accepted_cipher_suites:
                accepted_suite_list.append(accepted_suite.cipher_suite.name)

            all_accepted_suits[version] = accepted_suite_list
    
    return all_accepted_suits
        