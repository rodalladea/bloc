#!/usr/bin/env bash
# Local-only disposable infrastructure. Pass the verified multi-platform OCI layout.
set -euo pipefail
layout=${1:?verified OCI layout required}
mkdir -p evidence
exec > >(tee evidence/cluster.log) 2>&1
python3 tests/distribution/source.py
kind_name=bloc-distribution
registry=bloc-test-registry
if ! kind get clusters | grep -qx "$kind_name"; then
  # kind has no published node image for every patch; build the exact release.
  kind build node-image --type release v1.36.5 --image bloc-test-node:v1.36.5 \
    --base-image kindest/base:v20260820-69b56db7@sha256:8098fa3cae05bc15d9c4b93a566d19e1f8e65a25e26ebeb993b6cb41142cf791
  kind create cluster --name "$kind_name" --image bloc-test-node:v1.36.5 --wait 5m
fi
[[ $(kubectl config current-context) == "kind-$kind_name" ]]
if ! docker inspect "$registry" >/dev/null 2>&1; then
  docker run -d --restart=unless-stopped -p 127.0.0.1:5001:5000 --name "$registry" registry@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8
fi
python3 scripts/distribution/wait_registry.py
if ! docker network inspect kind --format '{{json .Containers}}' | grep -q '"Name":"bloc-test-registry"'; then
  docker network connect kind "$registry"
fi
for node in $(kind get nodes --name "$kind_name"); do
  docker exec "$node" mkdir -p /etc/containerd/certs.d/localhost:5001
  printf '[host."http://bloc-test-registry:5000"]\n  capabilities = ["pull", "resolve"]\n' |
    docker exec -i "$node" sh -c 'cat > /etc/containerd/certs.d/localhost:5001/hosts.toml'
done
fixture_dir=$(mktemp -d)
forward_pid=
cleanup() {
  if [[ -n "$forward_pid" ]]; then kill "$forward_pid" 2>/dev/null || true; fi
  rm -rf "$fixture_dir"
}
trap cleanup EXIT
python3 - "$layout" "$fixture_dir" <<'PYTHON'
import json, shutil, sys
from pathlib import Path
sys.path.insert(0, 'scripts/distribution')
from oci import Layout, Registry, descriptor, encode
source=Layout(sys.argv[1])
target=Path(sys.argv[2])
shutil.copytree(source.path,target/'b')
other=Layout(target/'b')
index=json.loads(other.read(other.root()['digest']))
# A fixture-only config label distinguishes B without changing the application.
index['manifests']=[item for item in index['manifests'] if item.get('platform',{}).get('os')=='linux']
for entry in index['manifests']:
    manifest=json.loads(other.read(entry['digest']))
    config=json.loads(other.read(manifest['config']['digest']))
    config['config']['Labels']['bloc.test.fixture']='B'
    data=encode(config)
    other.put(data)
    manifest['config']=descriptor(data,manifest['config']['mediaType'])
    data=encode(manifest)
    other.put(data)
    entry.update(descriptor(data,entry['mediaType']))
other.set_root(encode(index))
registry=Registry('localhost:5001/bloc',insecure=True)
for label,layout in [('a',source),('b',other)]:
    registry.publish(layout,label)
    Registry('localhost:5001/bloc-mirror',insecure=True).publish(layout,label)
    (target/label).with_suffix('.ref').write_text('localhost:5001/bloc@'+layout.root()['digest'])
PYTHON
image_a=$(cat "$fixture_dir/a.ref")
image_b=$(cat "$fixture_dir/b.ref")
case $(docker info --format '{{.Architecture}}') in
  aarch64|arm64) platform=linux/arm64 ;;
  x86_64|amd64) platform=linux/amd64 ;;
  *) echo 'Unsupported test host architecture' >&2; exit 1 ;;
esac
docker pull --platform "$platform" localhost:5001/bloc:a
python3 tests/distribution/container.py --image localhost:5001/bloc:a --platform "$platform" \
  --oci-layout "$layout" --revision "$(git rev-parse HEAD)" --check C7 --check C8
kubectl apply -f tests/distribution/fixtures/ingress.yaml
kubectl -n bloc-ingress-fixture rollout status deployment/traefik --timeout=5m
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=bloc.example.test \
  -addext subjectAltName=DNS:bloc.example.test -keyout "$fixture_dir/tls.key" -out "$fixture_dir/tls.crt" 2>/dev/null
kubectl -n bloc-ingress-fixture port-forward deployment/traefik 18443:8443 >"$fixture_dir/forward.log" 2>&1 &
forward_pid=$!
python3 -u tests/distribution/cluster.py --image "$image_a" --image-b "$image_b" \
  --ingress-class bloc-test-traefik --ingress-url 127.0.0.1:18443 \
  --tls-cert "$fixture_dir/tls.crt" --tls-key "$fixture_dir/tls.key"
