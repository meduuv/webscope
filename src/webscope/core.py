from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(slots=True)
class Report:
    url: str
    status: int | None
    ip: list[str]
    tls_version: str | None
    cert_expires: str | None
    cert_days_left: int | None
    headers: dict[str, str]
    missing_security_headers: list[str]
    server: str | None
    error: str | None


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("URL cannot be empty")
    return value if "://" in value else f"https://{value}"


def _resolve(host: str, port: int) -> list[str]:
    try:
        return sorted(
            {
                result[4][0]
                for result in socket.getaddrinfo(
                    host,
                    port,
                    type=socket.SOCK_STREAM,
                )
            }
        )
    except OSError:
        return []


def _tls_details(host: str, port: int, timeout: float):
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            certificate = tls_sock.getpeercert()
            expires = certificate.get("notAfter")
            days_left = None
            if expires:
                expiry = datetime.strptime(
                    expires,
                    "%b %d %H:%M:%S %Y %Z",
                ).replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
            return tls_sock.version(), expires, days_left


def inspect(value: str, timeout: float = 6.0) -> Report:
    url = normalize_url(value)
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("invalid URL")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    ips = _resolve(host, port)
    tls_version = None
    cert_expires = None
    cert_days_left = None
    error_parts: list[str] = []

    if parsed.scheme == "https":
        try:
            tls_version, cert_expires, cert_days_left = _tls_details(
                host,
                port,
                timeout,
            )
        except (OSError, ssl.SSLError, ValueError) as exc:
            error_parts.append(f"TLS: {exc}")

    status = None
    headers: dict[str, str] = {}
    opener = build_opener(NoRedirect())
    request = Request(url, headers={"User-Agent": "WebScope/1.0"})

    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as exc:
        response = exc
    except (URLError, OSError, ValueError) as exc:
        error_parts.append(f"HTTP: {exc}")
        response = None

    if response is not None:
        status = getattr(response, "status", getattr(response, "code", None))
        headers = {key.lower(): value for key, value in response.headers.items()}

    missing = [name for name in SECURITY_HEADERS if name not in headers]
    return Report(
        url=url,
        status=status,
        ip=ips,
        tls_version=tls_version,
        cert_expires=cert_expires,
        cert_days_left=cert_days_left,
        headers=headers,
        missing_security_headers=missing,
        server=headers.get("server"),
        error="; ".join(error_parts) or None,
    )


def score(report: Report) -> int:
    points = 100
    points -= 10 * len(report.missing_security_headers)
    if report.url.startswith("http://"):
        points -= 20
    if report.cert_days_left is not None and report.cert_days_left < 30:
        points -= 20
    if report.error:
        points -= 15
    return max(0, points)
