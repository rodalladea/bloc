import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import corpus


def source(prefix):
    body = ("F" * 35 + ":2\r\n" + "0" * 35 + ":1\r\n").encode()
    checksum = base64.b64encode(hashlib.md5(body).digest()).decode()
    return corpus.decode_range(prefix, body, checksum)


class CorpusTests(unittest.TestCase):
    def test_range_integrity(self):
        body = ("0" * 35 + ":1\r\n").encode()
        for bad, checksum in [(body, None), (body, "bad"), (b"bad", None)]:
            with self.subTest(body=bad, checksum=checksum), self.assertRaises(ValueError):
                corpus.decode_range(0, bad, checksum)
        for bad in [("0" * 35 + ":0\r\n").encode(), body + body,
                    ("G" * 35 + ":1\r\n").encode(),
                    ("0" * 35 + ":-1\r\n").encode()]:
            md5 = base64.b64encode(hashlib.md5(bad).digest()).decode()
            with self.subTest(body=bad), self.assertRaises(ValueError):
                corpus.decode_range(0, bad, md5)

    def test_build_and_verify(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            corpus.prepare(root, source, total=3, reserve_bytes=0)
            manifest = corpus.verify(root, total=3)
            data = (root / "hashes.bin").read_bytes()
            self.assertEqual(manifest["record_count"], 6)
            self.assertEqual(manifest["byte_length"], 120)
            self.assertEqual(manifest["sha256"], hashlib.sha256(data).hexdigest())
            expected = b"".join(bytes.fromhex(prefix + suffix)
                for prefix in ("00000", "00001", "00002")
                for suffix in ("0" * 35, "F" * 35))
            self.assertEqual(data, expected)
            receipts = [json.loads(line) for line in (root / "receipts.jsonl").read_text().splitlines()]
            self.assertEqual([row["prefix"] for row in receipts], [0, 1, 2])
            self.assertEqual([row["end"] for row in receipts], [40, 80, 120])
            self.assertTrue(all(row["records"] == 2 for row in receipts))
            self.assertEqual([data[i:i+20] for i in range(0, len(data), 20)],
                sorted(set(data[i:i+20] for i in range(0, len(data), 20))))

    def test_failure_never_publishes(self):
        def fail(prefix):
            if prefix == 1:
                raise OSError("network unavailable")
            return source(prefix)
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(OSError):
                corpus.prepare(Path(root), fail, total=3, workers=1, reserve_bytes=0)
            self.assertFalse((Path(root) / "manifest.json").exists())
            with self.assertRaises(ValueError):
                corpus.verify(Path(root), total=3)

    def test_corruption_rejected(self):
        for file in ("hashes.bin", "receipts.jsonl"):
            with tempfile.TemporaryDirectory() as root:
                root = Path(root)
                corpus.prepare(root, source, total=3, reserve_bytes=0)
                with (root / file).open("r+b") as target:
                    target.write(b"!")
                with self.assertRaises(ValueError):
                    corpus.verify(root, total=3)

    def test_resume(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            def fail(prefix):
                if prefix == 1:
                    raise OSError("interruption")
                return source(prefix)
            with self.assertRaises(OSError):
                corpus.prepare(root, fail, total=3, workers=1, reserve_bytes=0)
            with (root / "hashes.bin").open("ab") as target:
                target.write(b"uncommitted tail")
            seen = []
            def resumed(prefix):
                seen.append(prefix)
                return source(prefix)
            corpus.prepare(root, resumed, total=3, workers=1, reserve_bytes=0)
            self.assertEqual(seen, [1, 2])
            self.assertEqual(corpus.verify(root, total=3)["record_count"], 6)

    def test_membership(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            corpus.prepare(root, source, total=3, reserve_bytes=0)
            records = (root / "hashes.bin").read_bytes()
            for i in (0, 2, 5):
                self.assertTrue(corpus.contains(root / "hashes.bin", records[i*20:(i+1)*20]))
            self.assertFalse(corpus.contains(root / "hashes.bin", b"\xff" * 20))
            self.assertFalse(corpus.contains(root / "hashes.bin", bytes.fromhex("00000" + "1" * 35)))

    def test_disk_reserve(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(corpus.shutil, "disk_usage") as usage:
                usage.return_value.free = 0
                with self.assertRaises(OSError):
                    corpus.prepare(Path(root), source, total=3, reserve_bytes=1024)
            self.assertFalse((Path(root) / "manifest.json").exists())

    def test_stale_manifest_stage_does_not_block_resume(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / "manifest.json.tmp").write_text("interrupted publication")
            corpus.prepare(root, source, total=3, reserve_bytes=0)
            self.assertEqual(corpus.verify(root, total=3)["record_count"], 6)

    def test_source_receipt_fields_required(self):
        for field, value in [("source_md5", None), ("source_md5", "bad"),
                             ("source_bytes", None), ("source_bytes", -1),
                             ("records", True)]:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as root:
                root = Path(root)
                corpus.prepare(root, source, total=3, reserve_bytes=0)
                path = root / "receipts.jsonl"
                rows = [json.loads(line) for line in path.read_text().splitlines()]
                if value is None:
                    del rows[0][field]
                else:
                    rows[0][field] = value
                path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                with self.assertRaises(ValueError):
                    corpus.verify(root, total=3)

    def test_oversized_receipt_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / "hashes.bin").touch()
            (root / "receipts.jsonl").write_bytes(b" " * 4096)
            with self.assertRaises(ValueError):
                corpus.scan(root, 3, allow_partial=True)

    def test_checkpoint_sync_failure_does_not_duplicate_receipts(self):
        real_sync = corpus.sync
        failed = False
        def fail_after_flush(file):
            nonlocal failed
            real_sync(file)
            if Path(file.name).name == "receipts.jsonl" and not failed:
                failed = True
                raise OSError("receipt sync failure")
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            with patch.object(corpus, "sync", fail_after_flush), self.assertRaises(OSError):
                corpus.prepare(root, source, total=65, reserve_bytes=0)
            rows = [json.loads(line) for line in (root / "receipts.jsonl").read_text().splitlines()]
            self.assertEqual([row["prefix"] for row in rows], list(range(64)))
            self.assertFalse((root / "manifest.json").exists())
            corpus.prepare(root, source, total=65, reserve_bytes=0)
            self.assertEqual(corpus.verify(root, total=65)["record_count"], 130)
