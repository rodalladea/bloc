# installing bloc

bloc implements the administrator journey for development and evaluation with
shared PostgreSQL authority. Final native service acceptance and independent
verification remain required. MFA and production authentication approval remain
pending; application-user identity protocols are not implemented. A public release
exists only after its GitHub release records successful verification of both
packages; source changes do not publish a release.

Follow [administrator operations](administrator-access.md) first to provision
PostgreSQL 17/18, verified TLS, separate roles, explicit migrations, runtime secret
files, trusted HTTPS ingress, and backup/restore fencing. Serving replicas never
migrate automatically or receive operator/migrator credentials.

The initial exercise baseline is Helm **4.3.1** and Kubernetes **1.36.5**.
The image supports **linux/amd64** and **linux/arm64**. Other cluster versions,
Helm 3, and production resource sizing are not established by this baseline.
Use the actual verification evidence linked from the release notes.

## Container

After the `v0.0.1` release is complete, an anonymous client can run:

```sh
docker pull ghcr.io/rodalladea/bloc:v0.0.1
docker run --rm --name bloc --read-only --cap-drop ALL \
  --security-opt no-new-privileges -p 127.0.0.1:3000:3000 \
  --mount type=bind,src="$PWD/runtime-secrets",dst=/run/bloc,readonly \
  --env BLOC_DATABASE_URL_FILE=/run/bloc/runtime-url \
  --env BLOC_DATABASE_CA_FILE=/run/bloc/ca.crt \
  --env BLOC_ABUSE_KEY_FILE=/run/bloc/abuse-key \
  --env BLOC_CANONICAL_ORIGIN=https://bloc.example.test \
  --env BLOC_TRUSTED_PROXY_CIDRS=127.0.0.1/32 \
  --env MALLOC_MMAP_THRESHOLD_=131072 --cpus 1 --memory 512m --memory-swap 512m \
  ghcr.io/rodalladea/bloc:v0.0.1
```

In another terminal, `curl --fail http://127.0.0.1:3000/healthz` returns `ok`
and a newline. The image defaults to non-root execution, `0.0.0.0:3000`, and
`RUST_LOG=info`. Override `BLOC_BIND_ADDR` and `RUST_LOG` with Docker `--env`;
when changing the listener port, change the port mapping too. Source execution
still defaults to `127.0.0.1:3000`. A shared primary and a runtime-only `runtime-secrets` directory are required; no
writable application filesystem is required. Configure the actual immediate proxy
CIDRs (container peers may differ from host loopback). Stop with
`docker stop --timeout 30 bloc`.
For an immutable deployment identity, use the image digest in the release notes.

## Install into Kubernetes

Use your operator-managed Kubernetes context and a namespace you intend to modify.
Save configuration outside the cluster, for example in `bloc-values.yaml`:

```yaml
replicaCount: 2
logLevel: info
access:
  secretName: bloc-database
  canonicalOrigin: https://bloc.example.test
  trustedProxyCIDRs: 10.244.0.0/16
```

The CIDR above is illustrative: replace it with the actual immediate ingress
peer ranges and restrict network access accordingly. Before installation, provision
the operator-owned Secret keys and run the explicit migration workload described
in the administrator runbook. Do not put credential values in Helm values.

The released chart already contains the verified multi-platform image digest.
Keep image overrides out of ordinary saved values so an upgrade selects the new
chart's image. The source chart deliberately has an empty digest and requires an
explicit real test digest; it is not a releasable package as checked out.

Once `0.0.1` is published:

```sh
helm install bloc oci://ghcr.io/rodalladea/charts/bloc \
  --version 0.0.1 --namespace bloc --create-namespace \
  --values bloc-values.yaml --wait=watcher --timeout 5m
kubectl --namespace bloc get deployment bloc-bloc
kubectl --namespace bloc port-forward service/bloc-bloc 3000:80
```

In another terminal:

```sh
curl --fail http://127.0.0.1:3000/healthz
curl --fail http://127.0.0.1:3000/readyz
```

The default chart creates a namespaced Deployment and ClusterIP Service, without
an Ingress or cluster-wide resources. Each replica listens on port 3000 behind
Service port 80. It runs as UID/GID 65532, with a read-only root filesystem, all
Linux capabilities dropped, privilege escalation disabled, RuntimeDefault seccomp,
and no mounted service-account token.

Defaults request100m CPU/128Mi memory and limit1CPU/512Mi memory, with explicit
Linux/glibc allocator policy. Native full-service acceptance remains a separate
gate. RollingUpdate uses zero unavailable replicas and one surge replica; allow
spare scheduling capacity. Termination grace is30seconds. Readiness checks
`/readyz` (compatible writable primary), while liveness checks `/healthz` (process),
every10seconds with2-second timeouts and failure threshold3. Dependency failure
removes a replica from traffic without treating a live process as dead.

## Configuration

The [values file](../charts/bloc/values.yaml) and
[schema](../charts/bloc/values.schema.json) define the public keys:

| Key | Contract |
| --- | --- |
| `replicaCount` | Integer >= 0; zero deliberately scales down |
| `image.repository` | Nonempty repository without tag/digest; default `ghcr.io/rodalladea/bloc` |
| `image.digest` | `sha256:` plus 64 lowercase hex digits; release packaging supplies it |
| `logLevel` | Nonempty Rust log filter, default `info` |
| `resources` | Requests/limits maps with string quantities; Kubernetes validates quantities |
| `nodeSelector` | String-to-string map, default `{}` |
| `tolerations` | Array of objects, default `[]` |
| `affinity` | Object, default `{}` |
| `access.secretName` | Operator-owned Secret reference; runtime mounts only runtime-url/ca.crt/abuse-key |
| `access.canonicalOrigin` | Exact public HTTPS origin |
| `access.trustedProxyCIDRs` | Explicit immediate peer CIDRs; forwarding headers are overwritten by ingress |
| `access.migrationJob` | Optional distinct-credential explicit migration Job; defaultfalse |
| `access.operatorPod` | Optional operator-only sleeping Pod for attached exec; defaultfalse |
| `access.maintenanceJob` | Optional maintenance-credential daily CronJob; defaultfalse |
| `ingress.enabled` | Boolean, default `false` |
| `ingress.className` | Empty uses the operator's default class |
| `ingress.hostname` | Required DNS hostname when enabled; no scheme/path |
| `ingress.annotations` | String-to-string map |
| `ingress.tlsSecretName` | Required existing secret name when enabled |

Port, bind address, probes, security policy, and Service type are chart-controlled.
There is no `image.tag` or arbitrary environment override. Unknown top-level,
image, and ingress keys fail schema validation. Do not disable schema validation.
Validation cannot establish image reachability, capacity, DNS, or secret existence.
Mirror overrides must copy the selected image without changing its digest.

## Optional ingress

Provide a controller, working DNS pointing to it, and an existing TLS secret in
the release namespace. Add these settings to the saved values:

```yaml
ingress:
  enabled: true
  className: your-ingress-class
  hostname: bloc.example.test
  annotations: {}
  tlsSecretName: bloc-example-tls
```

The chart routes `/` to the Service. TLS terminates at the operator's controller;
the controller connects upstream over HTTP. The chart creates no controller,
certificate, or TLS secret, and does not infer proxy trust from Ingress metadata. Configure `access` explicitly;
ingress must overwrite forwarding headers and preserve canonical Host.
After installation, verify `curl --fail https://bloc.example.test/healthz` using
your certificate trust configuration; do not infer HTTPS success from Pod readiness.

Distinguish failures before changing the application:

| Symptom | Inspect |
| --- | --- |
| Pod not ready | `kubectl -n bloc describe pod`, logs, scheduling and probe events; test Service port-forward |
| No controller handling Ingress | `kubectl get ingressclass`, controller deployment/events, and selected class |
| Host does not resolve or resolves incorrectly | Operator DNS records and controller address; Pod health is independent |
| TLS failure | `kubectl -n bloc get secret bloc-example-tls`, certificate hostname/expiry/trust, controller events |
| Ingress exists but requests fail | `kubectl -n bloc describe ingress bloc-bloc`, Service endpoints and controller logs |

## Upgrade and recover

Publishing never changes an existing installation. First save your values and
record `helm history bloc --namespace bloc` and the current image digest. Back up the primary first. For schema changes, fence ingress and coordinate
explicit migrations and all replicas; automatic image rollback cannot undo a schema
change or replace the restore/invalidate-access/recovery procedure. Read
the selected release's limitations, then replace `0.0.2` below with an actual
published target version (it is an example, not a claim of availability):

```sh
helm upgrade bloc oci://ghcr.io/rodalladea/charts/bloc \
  --version 0.0.2 --namespace bloc --values bloc-values.yaml \
  --wait=watcher --timeout 5m --rollback-on-failure
```

Preserve the command's exit status. A nonzero result means the upgrade failed,
even when Helm restores the previous successful revision. The five-minute timeout
is a per-operation wait budget, not a bound on upgrade plus recovery and diagnostics.
After success, inspect `helm history`, the selected Deployment image digest, and
repeat the HTTP check through a fresh Service port-forward.

On failure, read Helm's rollback output and inspect:

```sh
helm history bloc --namespace bloc
helm status bloc --namespace bloc
kubectl --namespace bloc get deployment,pods,endpointslices
kubectl --namespace bloc get events --sort-by=.metadata.creationTimestamp
```

Verify the previous digest is restored and HTTP responds before declaring recovery
successful. If rollback also fails, report **upgrade failed; recovery failed**,
including the rollback diagnostic. A lost cluster connection means restoration
cannot be confirmed; restore connectivity and inspect history before another write.
Do not convert failure to success with `|| true` or continue a rollout blindly.

For explicit rollback, select a known successful revision from history. Here `1`
is an example revision, not necessarily your intended target:

```sh
helm rollback bloc 1 --namespace bloc --wait=watcher --timeout 5m
```

Check its exit status, selected digest, and HTTP response again. Report failed
recovery separately from the original upgrade failure. Historical artifacts are
retained for rollback, without promising ongoing security maintenance. Before a
public predecessor exists, tests use clearly labeled local A/B fixtures; repeat
the upgrade exercise with the actual predecessor at the first feature release.

## Uninstall

This removes the selected release's workload. Confirm the release and namespace
against `helm list --namespace bloc`, then explicitly run:

```sh
helm uninstall bloc --namespace bloc --wait --timeout 5m
```

Chart-owned resources are removed. Operator-owned TLS secrets, namespace, ingress
controller, and DNS remain. PostgreSQL administrator, session and audit data and operator-owned credentials
remain external; uninstall does not erase them. Follow the backup/restore runbook
when reusing a restored database, and require explicit operator action before
removing persistent authority.
