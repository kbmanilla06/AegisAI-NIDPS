from pathlib import Path

# Invocation-specific patterns for real enforcement / OS side effects. These are call
# forms, never bare words, so a data-only detection regex that *names* these tools
# (e.g. the prevention preview guard) is not itself a violation.
FORBIDDEN = (
    'subprocess.run(["iptables"',
    'subprocess.run(["nft"',
    'subprocess.run(["pfctl"',
    "subprocess.Popen(",
    'os.system("iptables',
    'os.system("nft',
    'os.system("pfctl',
    "socket.socket(",
    "privileged: true",
    "network_mode: host",
    "NET_ADMIN",
    "NET_RAW",
    "NET_BROADCAST",
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
