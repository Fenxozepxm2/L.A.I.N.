import re

# Правило 1: Проверка CSP
def check_csp(value: str | None) -> str | None:
    if not value:
        return 'Отсутствует Content Security Policy (риск XSS)'
    return None

# Правило 2: Проверка X-Frame-Options
def check_x_frame(value: str | None) -> str | None:
    if not value:
        return 'Отсутствует защита от кликджекинга (Clickjacking)'
    
    val_upper = value.upper()
    if "DENY" not in val_upper and "SAMEORIGIN" not in val_upper:
        return f'Небезопасное значение "{value}" (риск Clickjacking)'
    return None

# Правило 3: Проверка HSTS
def check_hsts(value: str | None) -> str | None:
    if not value:
        return 'Отсутствует принудительное шифрование HSTS (риск MITM)'
    
    if "max-age=" in value:
        try:
            # Вытаскиваем число секунд из max-age=31536000
            age = int(value.split("max-age=")[1].split(";")[0])
            if age < 15768000: # меньше полугода
                return f'Слишком короткий период HSTS max-age={age} (рекомендуется от 15768000)'
        except (ValueError, IndexError):
            pass
    return None

# Правило 4: Проверка X-Content-Type-Options
def check_x_content_type(value: str | None) -> str | None:
    if not value or value.lower().strip() != "nosniff":
        return 'Отсутствует или неверно настроен X-Content-Type-Options: nosniff (риск MIME-sniffing)'
    return None


# Правило 5: Проверка Referrer-Policy
def check_referrer_policy(value: str | None) -> str | None:
    if not value:
        return 'Отсутствует Content Security Policy / Referrer-Policy (Риск утечки конфиденциальных URL-адресов во внешние сети)'
    
    val_lower = value.lower().strip()
    # Безопасные варианты, которые мы одобряем
    safe_values = ["no-referrer", "same-origin", "strict-origin-when-cross-origin"]
    
    # Если значение небезопасное или равно unsafe-url
    if val_lower == "unsafe-url" or not any(safe in val_lower for safe in safe_values):
        return f'Небезопасная политика Referrer "{value}" (Риск утечки конфиденциальных URL-адресов во внешние сети)'
        
    return None

# Правило 6: Проверка Server и X-Powered-By (Раскрытие технологий)
def check_technology_disclosure(value: str | None) -> str | None:
    # Тут логика перевернутая: если заголовка нет — это отлично (сервер скрыл инфо)
    if not value:
        return None
        
    # Ищем цифры версий (например: 2.4, 1.18, 7.4) с помощью регулярного выражения
    # \d+ означает "одна или несколько цифр", потом точка \., потом снова цифры \d+
    if re.search(r'\d+\.\d+', value):
        return f'Раскрытие точной версии веб-сервера / программной платформы "{value}" (Облегчает злоумышленнику поиск целевых эксплойтов)'
        
    return None

    