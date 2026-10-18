import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import json

spec = importlib.util.spec_from_file_location("runner", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def exercise(self, threshold=None):
        calls = []

        def command(*args):
            calls.append(args)
            if args[:2] == ("docker", "create"):
                return "fixture-container"
            return json.dumps([{"HostConfig": {"Memory": 536870912,
                "MemorySwap": 536870912, "NanoCpus": 1000000000,
                "NetworkMode": "none"}, "Config": {"Env": [] if threshold is None
                else [f"MALLOC_MMAP_THRESHOLD_={threshold}"]}, "State": {"ExitCode": 0},
                "Image": "fixture-image"}])

        with tempfile.TemporaryDirectory() as root:
            paths = [Path(root) / name for name in ("csv", "meta", "state")]
            with patch.object(runner, "command", command), patch.object(runner.subprocess, "run"):
                runner.run_case("fixture-image", ["19456"], *paths, mmap_threshold=threshold)
            return calls[0], json.loads(paths[-1].read_text())

    def test_default_resources(self):
        args, state = self.exercise()
        for flag, value in (("--cpus", "1"), ("--memory", "512m"), ("--memory-swap", "512m")):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertNotIn("--env", args)
        self.assertEqual(state["memory"], 536870912)

    def test_explicit_allocator(self):
        args, state = self.exercise(131072)
        self.assertEqual(args[args.index("--env") + 1], "MALLOC_MMAP_THRESHOLD_=131072")
        self.assertEqual(state["allocator_environment"], ["MALLOC_MMAP_THRESHOLD_=131072"])
