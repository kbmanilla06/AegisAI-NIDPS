from pathlib import Path

FORBIDDEN = (
    'subprocess.run(["iptables"',
    'subprocess.run(["nft"',
    'os.system("iptables',
    'os.system("nft',
    "privileged: true",
    "network_mode: host",
    "NET_ADMIN",
)


def main() -> int:
    roots = [Path("apps"), Path("services"), Path("docker-compose.yml")]
    violations: list[str] = []
    for root in roots:
        files = [root] if root.is_file() else list(root.rglob("*"))
        for path in files:
            if not path.is_file() or path.suffix not in {
                ".py",
                ".yml",
                ".yaml",
            }:
                continue
            text = path.read_text(encoding="utf-8")
            for marker in FORBIDDEN:
                if marker in text:
                    violations.append(f"{path}: forbidden marker {marker!r}")
    if violations:
        print("\n".join(violations))
        return 1
    print("simulation-only static guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
