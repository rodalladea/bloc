"""Select source and database checks; unknown paths retain full validation."""
import os
from pathlib import PurePosixPath
import subprocess


def classify(paths):
    check = integration = False
    for path in paths:
        if (path.startswith(("docs/", ".github/ISSUE_TEMPLATE/"))
                or ("/" not in path and PurePosixPath(path).suffix == ".md")
                or path in ("LICENSE", "NOTICE", ".github/CODEOWNERS",
                            ".github/pull_request_template.md", ".github/dependabot.yml")):
            continue
        check = True
        if (path.startswith(("scripts/distribution/", "tests/distribution/"))
                or path == ".dockerignore"
                or (path.startswith(".github/workflows/") and path != ".github/workflows/ci.yml")):
            continue
        integration = True
    return check, integration


if __name__ == "__main__":
    base = os.environ.get("BASE", "")
    if not base or set(base) == {"0"}:
        selected = (True, True)
    else:
        paths = subprocess.check_output([
            "git", "diff", "--no-renames", "--name-only", "-z", base, os.environ["HEAD"]
        ]).decode().split("\0")
        selected = classify(path for path in paths if path)
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for name, enabled in zip(("check", "integration"), selected):
            output.write(f"{name}={str(enabled).lower()}\n")
