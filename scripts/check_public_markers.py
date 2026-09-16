"""Fail when tracked files contain secrets or generated private artifacts."""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys


PRIVATE_MARKERS_FILE = ".public-scan-private-markers"
PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
    re.IGNORECASE,
)
SECRET_ASSIGNMENT_RE = re.compile(
    rb"(?im)^[ \t]*(?:export[ \t]+)?"
    rb"([A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|API_KEY)[A-Z0-9_]*)"
    rb"[ \t]*[:=][ \t]*([^\s#]*)"
)
SAFE_EXAMPLE_VALUES = {
    b"", b"replace-me", b"changeme", b"example", b"dummy", b"test", b"file-token",
}
FORBIDDEN_SUFFIXES = (
    ".pem", ".key", ".crt", ".cer", ".csr", ".p12", ".pfx", ".log",
)
FORBIDDEN_PARTS = {"out", ".lego"}
CONFIG_SUFFIXES = {".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".config", ".example"}


def private_markers(root: Path) -> list[bytes]:
    """Load optional machine-local markers without tracking the file itself."""
    path = root / PRIVATE_MARKERS_FILE
    if not path.exists():
        return []
    return [
        line.strip().lower()
        for line in path.read_bytes().splitlines()
        if line.strip() and not line.lstrip().startswith(b"#")
    ]


def unsafe_secret_assignments(data: bytes) -> bool:
    for match in SECRET_ASSIGNMENT_RE.finditer(data):
        name = match.group(1).upper()
        if name.endswith((b"_ENDPOINT", b"_URL", b"_PATH", b"_FILE")):
            continue
        value = match.group(2).strip().strip(b"'\"").lower()
        if value not in SAFE_EXAMPLE_VALUES and not value.startswith(
            (b"example-", b"test-", b"dummy-", b"${", b"<")
        ):
            return True
    return False


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    tracked_output = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, stdout=subprocess.PIPE,
    ).stdout
    tracked = [item.decode("utf-8") for item in tracked_output.split(b"\0") if item]
    markers = private_markers(root)
    findings: list[str] = []

    for relative in tracked:
        path = Path(relative)
        lower_name = path.name.lower()
        lower_parts = {part.lower() for part in path.parts}
        if lower_name == ".env" or (
            lower_name.startswith(".env.") and lower_name != ".env.example"
        ):
            findings.append(f"{relative}: tracked environment file")
        if lower_name.endswith(FORBIDDEN_SUFFIXES):
            findings.append(f"{relative}: tracked certificate, key, CSR, or log artifact")
        if lower_parts & FORBIDDEN_PARTS:
            findings.append(f"{relative}: tracked generated/ACME artifact directory")

        candidate = root / relative
        if not candidate.is_file():
            continue
        data = candidate.read_bytes()
        if PRIVATE_KEY_RE.search(data):
            findings.append(f"{relative}: contains a PEM private-key marker")
        if path.suffix.lower() in CONFIG_SUFFIXES and unsafe_secret_assignments(data):
            findings.append(f"{relative}: contains a live-looking secret assignment")
        lower_data = data.lower()
        if any(marker in lower_data for marker in markers):
            findings.append(f"{relative}: contains a private local marker")

    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print(f"Public marker scan passed ({len(tracked)} tracked paths checked).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
