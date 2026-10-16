#!/usr/bin/env python3
"""C2: source startup preserves its loopback default."""
import os
import subprocess
import time
import urllib.request

subprocess.run(['cargo','build','--locked'],check=True)
environment={key:value for key,value in os.environ.items() if key not in ['BLOC_BIND_ADDR','RUST_LOG']}
process=subprocess.Popen(['target/debug/bloc'],env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
try:
    for attempt in range(60):
        if process.poll() is not None:
            raise AssertionError('source process failed: '+process.stdout.read())
        try:
            with urllib.request.urlopen('http://127.0.0.1:3000/healthz',timeout=1) as response:
                assert response.status==200 and response.read()==b'ok\n'
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise AssertionError('source process never became healthy')
finally:
    process.terminate()
    output=process.communicate(timeout=10)[0]
assert process.returncode==0,output
assert '127.0.0.1:3000' in output and 'bloc listening' in output,output
print('C2: source defaults to 127.0.0.1:3000; HTTP and SIGTERM passed')
