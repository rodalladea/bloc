"""Join both native CI records without manufacturing measurements."""
import json,subprocess,sys
from pathlib import Path
records=[json.loads(path.read_text()) for path in sorted(Path(sys.argv[1]).rglob('record.json'))]
assert len(records)==2, 'exactly two independently produced native records required'
assert {record['architecture'] for record in records}=={'amd64','arm64'}
output=Path(sys.argv[2]);output.write_text(json.dumps(records,indent=2)+'\n')
subprocess.run([sys.executable,str(Path(__file__).with_name('native_service_evidence.py')),str(output)],check=True)
