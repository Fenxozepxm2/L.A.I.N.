import asyncio
from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand, ServerScanResult

from cryptography.hazmat.primitives import hashes

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

        # смотрим что ваще пришло нам в скане
        accepted = await parse_sertifacates(result)
        print(accepted)

        # отчёт по tls сертификату
        certificate_info = await parse_tls_certificate_info(result)

        
        # пишем ещё анализ http заголовков 

        
async def parse_tls_certificate_info(result: ServerScanResult) -> None:
    certificate_info = result.scan_result.certificate_info

    if certificate_info.error_trace:
        return print("Scan not completed!")


    certificate_data = certificate_info.result
    deployments = certificate_data.certificate_deployments

    if not deployments:
        print("No certificate")

    main_deployment = deployments[0]

    leaf_cert = main_deployment.path_validation_results[0]

    # print(deployments[0].path_validation_results) # проверяем прошёл ли валидацию

    # print(deployments[0].path_validation_results[0].validation_error) # проверяем на ошибку

    errors = []
    for path_result in main_deployment.path_validation_results:
        if path_result.validation_error:
            errors.append(path_result.validation_error)
            print(f"Ошибка валидации {deployments[0].path_validation_results[0].validation_error}")

    
    is_valid = len(errors) == 0

    # print(deployments[0].path_validation_results[0].verified_certificate_chain[0]) # проверяем на верификацию пути

    subject = deployments[0].received_certificate_chain[0].subject.rfc4514_string() # кому выдан
    
    issuer = deployments[0].received_certificate_chain[0].issuer.rfc4514_string() # кем выдан


    public_key = deployments[0].received_certificate_chain[0].public_key() # имя ключа
    if hasattr(public_key, "key_size"):
        key_size = public_key.key_size
        key_type = "RSA"
    elif hasattr(public_key, "curve"):
        key_size = public_key.curve.key_size
        key_type = "ECDSA"



    fingerprint = deployments[0].received_certificate_chain[0].fingerprint(hashes.SHA256()).hex().upper()
    # print(fingerprint)
    


    return {
        "subject": str(subject),
        "issuer": str(issuer),
        "validation_errors": errors, 
        "key_size": key_size,
        "key_type": key_type,
        "not_before": leaf_cert.verified_certificate_chain[0].not_valid_before_utc.isoformat(),
        "not_after":  leaf_cert.verified_certificate_chain[0].not_valid_after_utc.isoformat(),
        "is_valid": is_valid,
        "fingerprint": fingerprint
    }




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
        