import httpx

from pydantic_models.models import HTTPResult
from web_analize.security_rules import (
    check_csp,
    check_hsts,
    check_referrer_policy,
    check_technology_disclosure,
    check_x_content_type,
    check_x_frame,
)

required_headers = [
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
]

SECURITY_RULES = {
    "Content-Security-Policy": check_csp,
    "X-Frame-Options": check_x_frame,
    "Strict-Transport-Security": check_hsts,
    "X-Content-Type-Options": check_x_content_type,
    # Добавляем новые правила:
    "Referrer-Policy": check_referrer_policy,
    "Server": check_technology_disclosure,
    "X-Powered-By": check_technology_disclosure,
}


async def get_http_headers(port: int, ip: str) -> HTTPResult:
    formatted_ip = f"[{ip}]" if ":" in ip else ip
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{formatted_ip}:{port}"

    try:
        report = {}

        async with httpx.AsyncClient(timeout=3.0, verify=False) as http_session:
            responce = await http_session.head(url, follow_redirects=True)

            if port == 80:
                if not responce.history and responce.url.scheme != "https":
                    report["HTTPS-Redirect"] = (
                        "Уязвимость: сервер не перенаправляет трафик на HTTPS."
                    )

            normalized_headers = {k.lower(): v for k, v in responce.headers.items()}

            for header_name, check_function in SECURITY_RULES.items():
                current_value = normalized_headers.get(header_name.lower())

                error_message = check_function(current_value)

                if error_message:
                    report[header_name] = error_message

            return report

    except Exception as e:
        raise e

    except httpx.HTTPError as http_err:
        print(
            f"[-] Сетевая ошибка [{type(http_err).__name__}] при запросе к {url}: {http_err}"
        )
        return {"Error": f"Сетевая ошибка: {http_err}"}

    except Exception as e:
        print(f"[!] Непредвиденная ошибка в get_http_headers для {ip}: {e}")
        return {"Error": str(e)}
