"""Build and retain the pre-MFA executable for real upgrade-direction proofs."""
import os
from pathlib import Path
import subprocess
import tarfile

BASE_REVISION = "db767253d83913396ca71fff90337f72cfe8f7e8"
ROOT = Path(__file__).resolve().parents[2]


def executable(path: Path) -> str:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("The retained pre-MFA binary must be an executable file")
    return str(resolved)


def ensure_binary(output: Path) -> str:
    """Use an explicit retained executable or build the exact base, failing closed."""
    supplied = os.environ.get("BLOC_MFA_LEGACY_BINARY")
    if supplied:
        return executable(Path(supplied))
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = output / "mfa-baseline"
    source.mkdir()
    archive = output / "mfa-baseline-source.tar"
    subprocess.run(
        ["git", "archive", "--format=tar", "--output", str(archive), BASE_REVISION],
        cwd=ROOT, check=True,
    )
    with tarfile.open(archive) as contents:
        contents.extractall(source, filter="data")
    archive.unlink()
    target = output / "mfa-baseline-target"
    log = output / "mfa-baseline-build.txt"
    print(f"Building pre-MFA executable; diagnostics: {log}", flush=True)
    with log.open("wb") as diagnostics:
        subprocess.run(
            ["cargo", "build", "--offline", "--locked", "--bin", "bloc", "--target-dir", str(target)],
            cwd=source, stdout=diagnostics, stderr=subprocess.STDOUT, check=True,
        )
    return executable(target / "debug" / "bloc")
