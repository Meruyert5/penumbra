"""Publish only the files that belong on the public dashboard site.

`pipeline.report` writes the built page and its assets to `docs/`. The design
notes, runbook, and tuning log also live under `docs/` for contributors, so the
Pages workflow must not upload the whole directory. This step copies the public
surface into `site/`: the dashboard, its assets, and the published case files.

Usage:
    python -m pipeline.publish
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from pipeline.common import DOCS_DIR, ROOT

SITE_DIR = ROOT / "site"
PUBLIC_DIRS = ("assets", "cases")


def publish(docs_dir: Path = DOCS_DIR, site_dir: Path = SITE_DIR) -> dict[str, int]:
    """Rebuild the public site from the generated dashboard.

    Args:
        docs_dir: Directory produced by ``pipeline.report``.
        site_dir: Destination directory. It is replaced on every run.

    Returns:
        Counts of copied files and directories for the caller to print.
    """
    index = docs_dir / "index.html"
    if not index.is_file():
        raise SystemExit(f"Dashboard not built: {index} is missing. Run python -m pipeline.report first.")

    if site_dir.exists():
        shutil.rmtree(site_dir)
    site_dir.mkdir(parents=True)
    (site_dir / ".nojekyll").write_text("", encoding="utf-8")
    shutil.copy2(index, site_dir / "index.html")

    copied_files = 1
    copied_dirs = 0
    for name in PUBLIC_DIRS:
        source = docs_dir / name
        if not source.exists():
            continue
        target = site_dir / name
        shutil.copytree(source, target)
        copied_files += sum(1 for path in target.rglob("*") if path.is_file())
        copied_dirs += 1

    return {"files": copied_files, "directories": copied_dirs}


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish the Penumbra dashboard site")
    parser.add_argument("--docs", default=str(DOCS_DIR), help="Built dashboard directory")
    parser.add_argument("--out", default=str(SITE_DIR), help="Public site directory")
    args = parser.parse_args()

    counts = publish(Path(args.docs), Path(args.out))
    print(f"Published {counts['files']} files in {counts['directories']} directories to {args.out}")


if __name__ == "__main__":
    main()
