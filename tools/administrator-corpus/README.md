# Offline administrator password corpus preparation

This isolated Python 3 tool prepares public HIBP SHA-1 reference data for the
administrator prerequisite investigation. It is not linked into bloc and accepts
no passwords. It does not implement authentication or activate a database revision.

```sh
python3 -m unittest discover -s tools/administrator-corpus -v
python3 tools/administrator-corpus/corpus.py prepare /path/to/new-snapshot --workers 16
python3 tools/administrator-corpus/corpus.py verify /path/to/new-snapshot
```

Preparation visits all 1,048,576 prefixes over HTTPS. Each bounded response must
match Content-MD5 and contain unique 35-hex-character SHA-1 suffixes with positive
counts. It sorts each range, discards counts, and appends full 20-byte digests in
prefix order. It never keeps the full source text or full corpus in memory.
Content-MD5 checks transport integrity; it is not a signature or snapshot authority.
The complete artifact gets a SHA-256 revision and retrieval timestamp. The live
API can change during a download; this is a complete traversal collected over an
interval, not a claim of an upstream point-in-time snapshot.

At most twice the worker count of responses are pending. Requests time out after
30 seconds and retry at most five times with backoff capped at ten seconds.
Preparation keeps a 10 GiB free-space reserve and stops without publication if
that reserve is reached. Actual dataset bytes and duration are evidence outputs,
not inferred guarantees. Choose a persistent destination for ongoing operation;
`/private/tmp` is only appropriate for this recoverable investigation.

`hashes.bin` is appended before durable `receipts.jsonl` records commit batches
of up to 64 prefixes. Binary fsync precedes journal fsync; handled failures flush
completed work, and abrupt failure may discard the uncommitted batch.
Receipts retain source Content-MD5, source byte count, output SHA-256,
record count and cumulative offset. A single-writer file lock protects preparation.
Restart the same command to verify committed ranges, discard an uncommitted data
tail and resume. A damaged receipt journal fails closed; preserve it for diagnosis.
No automatic repair of corrupt committed evidence is attempted.

The tool re-reads every range, checks order, coverage, length and checksum, then
atomically publishes `manifest.json`. Published directories cannot be prepared
again. A partial download has no valid manifest. Test fixtures explicitly mark
`complete_corpus=false`; the CLI cannot publish a subset as a complete dataset.
The manifest must pass `verify` before an operator treats it as reference data.
The standalone exact-membership function uses seek/read binary search; callers
must verify and pin the immutable artifact before using it. It is a preparation
probe, not the final Rust password-screening adapter.

Monthly refresh uses a new directory; retain the previous valid revision until
preparation, verification, distribution and shared activation succeed. This tool
does not remove previous snapshots, provision fleet storage or activate a revision.

Sources: [HIBP API](https://haveibeenpwned.com/API/v3#PwnedPasswords) and
[official downloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader).
The direct bounded converter avoids retaining both a large text corpus and binary
index. HIBP permits offline download; the published corpus terms require no
license or attribution, although attribution is welcomed. SHA-1 here identifies
membership only; it is not a credential hash. No upstream code is vendored.
