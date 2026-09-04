import argparse
import json
from dataclasses import asdict

from .core import inspect, score


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webscope",
        description="Inspect a website's transport and security posture.",
    )
    parser.add_argument("url", help="Website hostname or URL")
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        dest="json_output",
        help="Print machine-readable JSON",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=6.0,
        help="Network timeout in seconds",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    report = inspect(args.url, timeout=args.timeout)
    payload = asdict(report)
    payload["score"] = score(report)

    if args.json_output:
        print(json.dumps(payload, indent=2))
        return

    print(f"URL: {report.url}")
    print(f"Status: {report.status or 'unavailable'}")
    print(f"Score: {payload['score']}/100")
    print(f"IPs: {', '.join(report.ip) or 'unresolved'}")
    print(f"TLS: {report.tls_version or 'n/a'}")
    print(
        "Certificate days left: "
        + (
            str(report.cert_days_left)
            if report.cert_days_left is not None
            else "n/a"
        )
    )
    print(
        "Missing security headers: "
        + (
            ", ".join(report.missing_security_headers)
            if report.missing_security_headers
            else "none"
        )
    )
    if report.server:
        print(f"Server header: {report.server}")
    if report.error:
        print(f"Notes: {report.error}")


if __name__ == "__main__":
    main()
