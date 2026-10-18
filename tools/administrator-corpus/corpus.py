"""Prepare immutable offline HIBP reference data; never accepts passwords."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time
import urllib.error
import urllib.request

TOTAL = 16 ** 5
WIDTH = 20
MAX_RANGE_BYTES = 4 * 1024 * 1024
LINE = re.compile(rb"([0-9A-F]{35}):([1-9][0-9]*)")


def decode_range(prefix, body, content_md5):
    if not 0 <= prefix < TOTAL or not body or len(body) > MAX_RANGE_BYTES:
        raise ValueError("invalid prefix or range size")
    checksum = base64.b64encode(hashlib.md5(body).digest()).decode("ascii")
    if content_md5 != checksum:
        raise ValueError("missing or mismatched Content-MD5")
    records = []
    for line in body.splitlines():
        match = LINE.fullmatch(line)
        if match is None:
            raise ValueError("invalid SHA-1 suffix or positive count")
        records.append(bytes.fromhex(f"{prefix:05X}" + match[1].decode("ascii")))
    records.sort()
    if any(a == b for a, b in zip(records, records[1:])):
        raise ValueError("duplicate digest in range")
    data = b"".join(records)
    return data, {"source_md5": checksum, "source_bytes": len(body),
                  "sha256": hashlib.sha256(data).hexdigest(), "records": len(records)}


def download(prefix):
    request = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix:05X}",
        headers={"User-Agent": "bloc-offline-corpus-preparation/1", "Accept-Encoding": "identity"})
    for attempt in range(6):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status != 200:
                    raise ValueError("range did not return 200")
                body = response.read(MAX_RANGE_BYTES + 1)
                return decode_range(prefix, body, response.headers.get("Content-MD5"))
        except (OSError, ValueError):
            if attempt == 5:
                raise
            time.sleep(min(2 ** attempt, 10))


def sync(file):
    file.flush()
    os.fsync(file.fileno())


def scan(root, total, allow_partial=False):
    """Validate every committed range, retaining only a single range in memory."""
    count, offset, prefix = 0, 0, 0
    digest = hashlib.sha256()
    try:
        with (root / "hashes.bin").open("rb") as data, (root / "receipts.jsonl").open("rb") as receipts:
            while line := receipts.readline(2049):
                if len(line) > 2048 or not line.endswith(b"\n"):
                    raise ValueError("invalid receipt line length or termination")
                row = json.loads(line)
                for key in ("prefix", "records", "end", "source_bytes"):
                    if type(row[key]) is not int:
                        raise ValueError("receipt numeric field is not an integer")
                if not isinstance(row["source_md5"], str) or not re.fullmatch(
                        r"[A-Za-z0-9+/]{22}==", row["source_md5"]):
                    raise ValueError("invalid source MD5 receipt")
                if not 0 < row["source_bytes"] <= MAX_RANGE_BYTES:
                    raise ValueError("invalid source byte count")
                if row["prefix"] != prefix or prefix >= total or row["records"] < 1:
                    raise ValueError("incomplete or out-of-order prefix receipts")
                size = row["records"] * WIDTH
                if size > MAX_RANGE_BYTES or row["end"] != offset + size:
                    raise ValueError("invalid range length")
                chunk = data.read(size)
                if len(chunk) != size or hashlib.sha256(chunk).hexdigest() != row["sha256"]:
                    raise ValueError("range checksum mismatch")
                previous = None
                for i in range(0, size, WIDTH):
                    record = chunk[i:i + WIDTH]
                    if int.from_bytes(record[:3], "big") >> 4 != prefix:
                        raise ValueError("record in wrong prefix")
                    if previous is not None and record <= previous:
                        raise ValueError("records not sorted and unique")
                    previous = record
                digest.update(chunk)
                offset += size
                count += row["records"]
                prefix += 1
            if not allow_partial and (prefix != total or data.read(1)):
                raise ValueError("incomplete corpus or uncommitted bytes")
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("invalid corpus files") from error
    return prefix, offset, count, digest


def prepare(root, fetch=download, total=TOTAL, workers=8, reserve_bytes=10 * 1024 ** 3):
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (root / "manifest.json").exists():
            raise ValueError("published snapshot is immutable; choose a new directory")
        data_path, receipt_path = root / "hashes.bin", root / "receipts.jsonl"
        if data_path.exists() != receipt_path.exists():
            raise ValueError("data/receipt pair incomplete; preserve for diagnosis")
        if not data_path.exists():
            data_path.touch()
            receipt_path.touch()
        start, offset, count, digest = scan(root, total, allow_partial=True)
        with data_path.open("r+b") as data, receipt_path.open("ab") as receipts:
            data.truncate(offset)
            data.seek(offset)
            staged = []
            checkpoint_failed = False

            def checkpoint():
                nonlocal checkpoint_failed
                if staged:
                    # A failed append/fsync must never be replayed by error cleanup.
                    checkpoint_failed = True
                    # Binary durability precedes receipt durability; a crash can leave only a data tail.
                    sync(data)
                    receipts.write(b"".join(staged))
                    sync(receipts)
                    staged.clear()
                    checkpoint_failed = False

            with ThreadPoolExecutor(max_workers=workers) as pool:
                # At most two bounded ranges per worker can be in flight or buffered.
                pending = {}
                next_prefix = start
                try:
                    for prefix in range(start, total):
                        while next_prefix < min(total, prefix + 2 * workers):
                            pending[next_prefix] = pool.submit(fetch, next_prefix)
                            next_prefix += 1
                        chunk, receipt = pending.pop(prefix).result()
                        if shutil.disk_usage(root).free < reserve_bytes + len(chunk) + 65536:
                            raise OSError("disk reserve reached; preparation remains unpublished")
                        data.write(chunk)
                        offset += len(chunk)
                        count += receipt["records"]
                        digest.update(chunk)
                        receipt.update(prefix=prefix, end=offset)
                        staged.append((json.dumps(receipt, separators=(",", ":")) + "\n").encode())
                        if len(staged) == 64:
                            checkpoint()
                        if (prefix + 1) % 1024 == 0:
                            print(json.dumps({"ranges": prefix + 1, "total": total,
                                              "bytes": offset, "records": count}), flush=True)
                finally:
                    if not checkpoint_failed:
                        checkpoint()
        # Re-read the entire artifact and receipts before publication.
        _, length, records, checked = scan(root, total)
        if checked.hexdigest() != digest.hexdigest():
            raise ValueError("final checksum differs from preparation")
        manifest = {"format_version": 1, "source": "HIBP Pwned Passwords SHA-1 ranges",
                    "retrieved_at": datetime.now(timezone.utc).isoformat(),
                    "prefix_count": total, "complete_corpus": total == TOTAL,
                    "record_count": records, "byte_length": length,
                    "sha256": checked.hexdigest(), "snapshot_id": checked.hexdigest()}
        temporary = root / "manifest.json.tmp"
        with temporary.open("w") as file:
            file.write(json.dumps(manifest, indent=2) + "\n")
            sync(file)
        temporary.replace(root / "manifest.json")
        print(json.dumps(manifest), flush=True)
        return manifest


def verify(root, total=TOTAL):
    _, size, count, digest = scan(root, total)
    try:
        manifest = json.loads((root / "manifest.json").read_text())
        expected = {"format_version": 1, "prefix_count": total,
                    "complete_corpus": total == TOTAL, "byte_length": size,
                    "record_count": count, "sha256": digest.hexdigest(),
                    "snapshot_id": digest.hexdigest()}
        if any(manifest.get(key) != value for key, value in expected.items()):
            raise ValueError("manifest mismatch")
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("no valid manifest") from error
    return manifest


def contains(path, digest):
    if len(digest) != WIDTH:
        raise ValueError("expected a 20-byte digest")
    with path.open("rb") as file:
        size = os.fstat(file.fileno()).st_size
        if size % WIDTH:
            raise ValueError("invalid record length")
        low, high = 0, size // WIDTH
        while low < high:
            middle = (low + high) // 2
            file.seek(middle * WIDTH)
            record = file.read(WIDTH)
            if len(record) != WIDTH:
                raise ValueError("truncated snapshot")
            if record == digest:
                return True
            if record < digest:
                low = middle + 1
            else:
                high = middle
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["prepare", "verify"])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--workers", type=int, choices=range(1, 33), default=8)
    args = parser.parse_args()
    if args.operation == "prepare":
        prepare(args.directory, workers=args.workers)
    else:
        print(json.dumps(verify(args.directory)))


if __name__ == "__main__":
    main()
