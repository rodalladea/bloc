"""Run the synthetic microbenchmark; this does not measure an HTTP service."""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
from pathlib import Path
import subprocess


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def run_case(image_id, parameters, csv_path, meta_path, state_path, mmap_threshold=None):
    allocator = [] if mmap_threshold is None else [
        "--env", f"MALLOC_MMAP_THRESHOLD_={mmap_threshold}"]
    container_id = command(
        "docker", "create", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--cpus", "1", "--memory", "512m", "--memory-swap", "512m",
        "--pids-limit", "32", *allocator, image_id, *parameters,
    )
    try:
        with csv_path.open("w") as out, meta_path.open("w") as err:
            subprocess.run(["docker", "start", "--attach", container_id],
                           stdout=out, stderr=err, check=True)
    finally:
        # Inspect before removing only the container created for this case.
        try:
            inspected = json.loads(command("docker", "inspect", container_id))[0]
            config = inspected["HostConfig"]
            state_path.write_text(json.dumps({
                "state": inspected["State"], "image_id": inspected["Image"],
                "memory": config["Memory"], "memory_swap": config["MemorySwap"],
                "nano_cpus": config["NanoCpus"], "network": config["NetworkMode"],
                "allocator_environment": [value for value in inspected["Config"]["Env"]
                                          if value.startswith(("MALLOC_", "GLIBC_TUNABLES="))],
            }, indent=2) + "\n")
        finally:
            subprocess.run(["docker", "rm", "--force", container_id],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="bloc-administrator-spike:local")
    parser.add_argument("--output", type=Path, default=Path("evidence/administrator-spike"))
    parser.add_argument("--mmap-threshold", type=int, choices=[131072],
                        help="Explicit glibc allocator diagnostic; default preserves original environment")
    case_names = [f"m{memory}-t{iterations}-c{concurrency}-{mode}-{password_input}"
                  for memory, iterations in [(65536, 3), (19456, 2)]
                  for concurrency in (1, 2)
                  for mode in ("hash", "verify", "unknown", "change")
                  for password_input in ("ascii", "unicode")]
    parser.add_argument("--case", choices=case_names, action="append",
                        help="Run only selected cases in a separate output directory; default is all 32")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.mkdir(exist_ok=False)
    image = json.loads(command("docker", "image", "inspect", args.image))[0]
    engine = json.loads(command("docker", "info", "--format", "{{json .}}"))
    aliases = {"aarch64": "arm64", "x86_64": "amd64"}
    engine_arch = aliases.get(engine["Architecture"], engine["Architecture"])
    if image["Os"] != "linux" or engine["OSType"] != "linux":
        raise SystemExit("The measurement gate requires Linux containers")
    if image["Architecture"] != engine_arch:
        raise SystemExit("Refusing cross-architecture/emulated measurements")
    lock = Path(__file__).with_name("Cargo.lock").read_bytes()
    metadata = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "image_id": image["Id"], "architecture": image["Architecture"],
        "engine_architecture": engine_arch, "kernel": engine["KernelVersion"],
        "virtualization": engine["OperatingSystem"], "toolchain": "1.98.1",
        "lockfile_sha256": hashlib.sha256(lock).hexdigest(),
        "source_sha256": hashlib.sha256(Path(__file__).with_name("src").joinpath("main.rs").read_bytes()).hexdigest(),
        "cpu_limit": 1, "memory_bytes": 536870912, "swap_bytes": 0,
        "mmap_threshold": args.mmap_threshold,
        "scope": "synthetic microbenchmark only; no HTTP, database, blocklist, or service overload evidence",
        "selected_cases": sorted(set(args.case)) if args.case else case_names,
    }
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    summary = []
    for memory, iterations in [(65536, 3), (19456, 2)]:
        for concurrency in (1, 2):
            for mode in ("hash", "verify", "unknown", "change"):
                for password_input in ("ascii", "unicode"):
                    name = f"m{memory}-t{iterations}-c{concurrency}-{mode}-{password_input}"
                    if args.case and name not in args.case:
                        continue
                    csv_path = args.output / f"{name}.csv"
                    meta_path = args.output / f"{name}.txt"
                    # Never reuse a previous run silently or mix separate experiments.
                    if csv_path.exists() or meta_path.exists():
                        raise SystemExit(f"Evidence already exists for {name}; choose a new output folder")
                    run_case(image["Id"], [str(memory), str(iterations), str(concurrency),
                             "200", mode, password_input], csv_path, meta_path,
                             args.output / f"{name}.container.json", args.mmap_threshold)
                    rows = list(csv.DictReader(io.StringIO(csv_path.read_text())))
                    if len(rows) != 200:
                        raise SystemExit(f"Incomplete measurement: {name}")
                    times = sorted(int(row["duration_us"]) for row in rows)
                    row = {
                        "case": name, "samples": len(times),
                        "p50_ms": times[math.ceil(len(times) * 0.50) - 1] / 1000,
                        "p95_ms": times[math.ceil(len(times) * 0.95) - 1] / 1000,
                        "max_ms": max(times) / 1000,
                    }
                    summary.append(row)
                    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
                    print(json.dumps(row), flush=True)
    metadata["finished_at"] = datetime.now(timezone.utc).isoformat()
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
