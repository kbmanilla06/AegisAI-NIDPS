#!/usr/bin/env python3
"""Create metadata-only Gate P4 reproducibility evidence.

The command is intentionally offline: it reads only an allowlisted set of
control files and never invokes Docker, a shell, a network client, a model, or
a dataset parser.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from aegis_services.reproducibility import ReproducibilityError, write_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = write_manifest(args.project_root, args.output)
    except (OSError, ReproducibilityError) as exc:
        print(f"reproducibility evidence blocked: {exc}")
        return 1
    print(f"reproducibility evidence written: {args.output.resolve()}")
    print(f"identity_sha256: {manifest['identity_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
