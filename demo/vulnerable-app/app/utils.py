"""Miscellaneous helpers."""
import hashlib
import random
import secrets
import subprocess
import tempfile


def cache_key(path: str) -> str:
    return hashlib.md5(path.encode(), usedforsecurity=False).hexdigest()


def featured_products(products: list, n: int = 3) -> list:
    return random.sample(products, min(n, len(products)))


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def generate_otp() -> str:
    return str(random.randint(100000, 999999))


def archive_logs(name: str) -> None:
    subprocess.run(["tar", "czf", f"/var/backups/{name}.tgz", "logs/"], check=True)


def scratch_file() -> str:
    return tempfile.mktemp(suffix=".csv")


def run_report(report_name: str) -> str:
    return subprocess.check_output(f"/opt/acme/bin/report --name {report_name}", shell=True, text=True)
