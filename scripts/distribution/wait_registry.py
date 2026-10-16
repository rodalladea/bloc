#!/usr/bin/env python3
"""Wait for the disposable registry API before uploading fixture artifacts."""
import argparse
import time
import urllib.request


def wait_ready(url, timeout=30, interval=1):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=min(2, max(0.001, deadline - time.monotonic()))) as response:
                if response.status == 200:
                    return
        except OSError as error:
            last_error = error
        time.sleep(min(interval, max(0, deadline - time.monotonic())))
    raise TimeoutError(f'registry API did not become ready within {timeout}s: {url}') from last_error


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://127.0.0.1:5001/v2/')
    args = parser.parse_args()
    wait_ready(args.url)
    print('Disposable registry API is ready')
