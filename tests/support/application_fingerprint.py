"""Fingerprint exactly the application files copied into the native image build."""
import hashlib
from pathlib import Path

def source_fingerprint():
    files=[Path(name) for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','Dockerfile']]
    for root in ['src','migrations','templates','assets']:
        files.extend(path for path in Path(root).rglob('*') if path.is_file())
    digest=hashlib.sha256()
    for path in sorted(files):
        digest.update(str(path).encode()+b'\0'+path.read_bytes()+b'\0')
    return digest.hexdigest()
