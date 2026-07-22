#!/usr/bin/env python3
"""Mirror the live Beyond Features agent implementation into this repository."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

FILES = (
    "functions/api/domain-research.ts",
    "functions/api/chat.ts",
    "functions/_lib/knowledge.ts",
    "src/components/DomainResearchDemo.astro",
    "src/components/Footer.astro",
    "src/components/ProfessionalChat.astro",
    "src/components/ProjectCard.astro",
    "src/content/projects/ai-security-research-agent-poc.md",
    "src/config.ts",
    "src/pages/about.astro",
    "src/pages/contact.astro",
    "src/pages/index.astro",
    "src/pages/projects/[id].astro",
    "src/pages/projects/index.astro",
    "src/pages/recruiter.astro",
    "src/pages/resume.astro",
    "src/pages/writing/index.astro",
    "src/styles/global.css",
)
REPOSITORY = "sdontogan/beyond-features"
DESTINATION = Path(__file__).resolve().parents[1] / "web-adaptation"


def git_revision(source: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()


def download_source() -> tuple[Path, str, tempfile.TemporaryDirectory[str]]:
    token = os.environ.get("WEBSITE_REPO_TOKEN", "")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "agent-web-sync",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    commit_url = f"https://api.github.com/repos/{REPOSITORY}/commits/main"
    request = urllib.request.Request(commit_url, headers=headers)
    with urllib.request.urlopen(request) as response:
        revision = json.load(response)["sha"]

    temporary = tempfile.TemporaryDirectory()
    archive_path = Path(temporary.name) / "source.tar.gz"
    archive_url = f"https://api.github.com/repos/{REPOSITORY}/tarball/{revision}"
    archive_request = urllib.request.Request(archive_url, headers=headers)
    with urllib.request.urlopen(archive_request) as response:
        archive_path.write_bytes(response.read())
    with tarfile.open(archive_path) as archive:
        archive.extractall(temporary.name, filter="data")
    source = next(path for path in Path(temporary.name).iterdir() if path.is_dir())
    return source, revision, temporary


def sync(source: Path, revision: str) -> None:
    for relative in FILES:
        source_file = source / relative
        if not source_file.is_file():
            raise FileNotFoundError(f"Missing website source file: {relative}")
        destination_file = DESTINATION / relative
        destination_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_file, destination_file)

    manifest = {
        "source": f"https://github.com/{REPOSITORY}",
        "commit": revision,
        "files": list(FILES),
    }
    (DESTINATION / "source.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path)
    args = parser.parse_args()

    temporary = None
    if args.source_dir:
        source = args.source_dir.resolve()
        revision = git_revision(source)
    else:
        source, revision, temporary = download_source()
    try:
        sync(source, revision)
    finally:
        if temporary:
            temporary.cleanup()
    print(f"Mirrored Beyond Features agent code at {revision[:7]}.")


if __name__ == "__main__":
    main()
