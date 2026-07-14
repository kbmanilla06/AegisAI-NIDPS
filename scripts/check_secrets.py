import re
from pathlib import Path

ASSIGNMENT = re.compile(
    r"(?i)(api[_-]?key|client[_-]?secret|password|private[_-]?key|token)\s*[:=]\s*['\"]?([^\s'\"]+)"
)
ALLOWLIST = {"", "<set-locally>", "unset"}
IGNORED_PARTS = {".git", "node_modules", "dist", "coverage", ".venv"}


def main() -> int:
    findings: list[str] = []
    for path in Path(".").rglob("*"):
        if not path.is_file() or any(part in IGNORED_PARTS for part in path.parts):
            continue
        if path.suffix not in {".yml", ".yaml", ".json", ".toml", ".env"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line_number, line in enumerate(text.splitlines(), start=1):
            match = ASSIGNMENT.search(line)
            value = match.group(2).rstrip(",}") if match else ""
            if (
                match
                and value not in ALLOWLIST
                and not value.startswith("$")
                and not value.endswith("validation-only")
            ):
                findings.append(f"{path}:{line_number}: possible hardcoded secret assignment")
    if findings:
        print("\n".join(findings))
        return 1
    print("secret assignment guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
