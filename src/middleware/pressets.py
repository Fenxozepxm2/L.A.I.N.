SCAN_PROFILES = {
    # 1. Призрак-Исследователь (Скрытный сбор)
    "p1": [
        '-sS', '-T2', '-Pn', 
        '--script=auth,default', 
        '--script-args=unsafe=0', 
        '--top-ports', '100'
    ],
    
    # 2. Тихий Наводчик (Сбалансированный сбор)
    "p2": [
        '-sS', '-T3', '-Pn', '-O', '-sV', '--version-light', 
        '--script=default,discovery', 
        '--top-ports', '1000'
    ],
    
    # 3. Аудит Уязвимостей (Безопасный поиск CVE)
    "p3": [
        '-sS', '-T4', '-O', '-sV', 
        '--script=vuln,vulners', 
        '--script-args=unsafe=0', 
        '--top-ports', '2000'
    ],
    
    # 4. Хакерский Пресет: Взломщик (Активный штурм и Брутфорс)
    "p4": [
        '-sS', '-sU', '-T4', '-O', '-sV', 
        '--script=vuln,auth,brute', 
        '-p', 'T:21,22,23,80,443,445,1433,3306,3389,5432,8080,U:53,67,68,161'
    ],
    
    # 5. Хакерский Пресет: Анализ Инфраструктуры (Тотальный Discovery)
    "p5": [
        '-sS', '-T4', '-A', 
        '--script=discovery,external', 
        '--top-ports', '5000'
    ],
    
    # 6. Тотальное выжигание (Maximum Aggressive & Unsafe)
    "p6": [
        '-sS', '-sU', '-T5', '-A', '--min-rate', '3000', 
        '--script=all', 
        '--script-args=unsafe=1', 
        '-p', 'T:1-65535,U:1-500'
    ]
}
