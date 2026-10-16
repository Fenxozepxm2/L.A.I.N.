import httpx

from pydantic_models.models import HTTPResult
from web_analize.security_rules import (
    check_csp,
    check_hsts,
    check_referrer_policy,
    check_technology_disclosure,
    check_x_content_type,
)

required_headers = [
    "content-security-policy",
    # "x-frame-options",
    "strict-transport-security",
]

SECURITY_RULES = {
    "Content-Security-Policy": check_csp,
    # "X-Frame-Options": check_x_frame,
    "Strict-Transport-Security": check_hsts,
    "X-Content-Type-Options": check_x_content_type,
    # Добавляем новые правила:
    "Referrer-Policy": check_referrer_policy,
    "Server": check_technology_disclosure,
    "X-Powered-By": check_technology_disclosure,
}


from pydantic_models.models import ScanResult

HTTPS_PORTS = {443, 8443}


async def get_http_headers(port: int, ip: str) -> HTTPResult:
    formatted_ip = f"[{ip}]" if ":" in ip else ip
    scheme = "https" if port in HTTPS_PORTS else "http"
    url = f"{scheme}://{formatted_ip}:{port}"

    async with httpx.AsyncClient(timeout=3.0, verify=False) as session:
        response = await session.head(url, follow_redirects=True)

        if response.status_code in (405, 501):
            response = await session.get(url, follow_redirects=True)

    report: dict[str, str] = {}

    if scheme == "http" and response.url.scheme != "https":
        report["HTTPS-Redirect"] = (
            "Уязвимость: сервер не перенаправляет трафик на HTTPS."
        )

    headers = dict(response.headers)
    normalized = {k.lower(): v for k, v in headers.items()}

    for header_name, check_function in SECURITY_RULES.items():
        if header_name == "Strict-Transport-Security" and scheme == "http":
            continue

        error_message = check_function(normalized.get(header_name.lower()))
        if error_message:
            report[header_name] = error_message

    return HTTPResult(
        url=str(response.url),
        status_code=response.status_code,
        headers=headers,
        server=response.headers.get("server"),
        redirect_url=str(response.url) if response.history else None,
        findings=ScanResult.model_validate(report),
    )
