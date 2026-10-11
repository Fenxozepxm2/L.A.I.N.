import asyncio
from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand, ServerScanResult


from pydantic_models.models import TlsVersionResult, CertificateInfoResult, AllTlsScanResult

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
        
        # пишем ещё анализ http заголовков 

        


async def parse_sertifacates(result: ServerScanResult, tls_version: list[str] = None) -> AllTlsScanResult: # пока что лист чуть позже добавь модель (по настроению)
    
    """
    Мастер-парсер: собирает шифры и сертификат из ServerScanResult 
    и упаковывает в единую Pydantic-модель AllTlsScanResult.
    """
    
    if not tls_version:
        # это приставки от _cipher_suites
        tls_version = ["tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"]
    
    parsed_ciphers = []
    
    for version in tls_version:
        full_name_tls_version = f"{version}_cipher_suites"

        tls_data = getattr(result.scan_result, full_name_tls_version, None)

        if not tls_data or tls_data.status.value != "COMPLETED":
            continue

        accepted_suite_list = [
            suite.cipher_suite.name for suite in tls_data.result.accepted_cipher_suites
        ]

        parsed_ciphers.append(TlsVersionResult(version=version, accepted_ciphers=accepted_suite_list))


        parsed_cert = None
    cert_info = result.scan_result.certificate_info
    
    if cert_info and cert_info.status.value == "COMPLETED" and cert_info.result.certificate_deployments:
        main_deployment = cert_info.result.certificate_deployments[0]
        received_leaf_cert = main_deployment.received_certificate_chain[0]
        
        # Сбор ошибок валидации
        errors = [
            path.validation_error for path in main_deployment.path_validation_results 
            if path.validation_error
        ]
        is_valid = len(errors) == 0
        
        # Парсинг публичного ключа
        public_key = received_leaf_cert.public_key()
        key_size = None
        key_type = "UNKNOWN"
        
        if hasattr(public_key, "key_size"):
            key_size = public_key.key_size
            key_type = "RSA"
        elif hasattr(public_key, "curve"):
            key_size = public_key.curve.key_size
            key_type = "ECDSA"
            
        # Генерация фингерпринта
        fingerprint = received_leaf_cert.fingerprint(hashes.SHA256()).hex().upper()
        
        # Безопасное извлечение дат с учетом предупреждений (совместимость с UTC)
        if hasattr(received_leaf_cert, "not_valid_before_utc"):
            not_before = received_leaf_cert.not_valid_before_utc.isoformat()
            not_after = received_leaf_cert.not_valid_after_utc.isoformat()
        else:
            not_before = received_leaf_cert.not_valid_before.isoformat()
            not_after = received_leaf_cert.not_valid_after.isoformat()
            
        # Упаковываеn в под-модель CertificateInfoResult
        parsed_cert = CertificateInfoResult(
            subject=received_leaf_cert.subject.rfc4514_string(),
            issuer=received_leaf_cert.issuer.rfc4514_string(),
            is_valid=is_valid,
            key_type=key_type,
            key_size=key_size,
            fingerprint_sha256=fingerprint,
            not_before=not_before,
            not_after=not_after,
            validation_errors=errors
        )

    # Извлекает сканируемый хост напрямую из объекта результатов sslyze
    hostname = result.scan_result.certificate_info.result.hostname_used_for_server_name_indication

    return AllTlsScanResult(
        target_host=hostname,
        ciphers=parsed_ciphers,
        certificate=parsed_cert
    )

        