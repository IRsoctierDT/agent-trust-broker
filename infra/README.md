# infra/ — containerized PEP gateway (rootless podman)

The ATB-03 enforcement point ships as a rootless, daemonless container so the
reference monitor gets OS-level isolation on top of its own fail-closed logic
(defense in depth, AGENTS.md §3). The recipe targets podman; the Containerfile
is plain OCI and builds with docker unchanged.

## Build

```bash
podman build -t ianua-atb -f infra/Containerfile .
```

## Run (secure defaults)

```bash
podman run --rm -i \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --network=none \
  -v atb-chain:/var/lib/atb \
  -e ATB_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')" \
  ianua-atb
```

Why each flag:

| Flag | Control |
|---|---|
| rootless podman (no daemon) | no privileged broker process to compromise |
| `--read-only` | tamper-resistant rootfs; only the chain volume is writable |
| `--cap-drop=all` + `no-new-privileges` | least privilege, no escalation path |
| `--network=none` | the gateway is stdio-only; egress exists solely as an ATB escalation, so the container needs no network at all |
| `-v atb-chain:/var/lib/atb` | the hash-chained audit log survives the container |
| `ATB_SIGNING_KEY` via `-e` / secret store | keys injected at run time, never in the image |

The gateway speaks newline-delimited JSON-RPC on stdio (`initialize`,
`tools/list`, `tools/call`); wire it to an agent runtime with `podman run -i`
or a systemd/Quadlet unit. Resolve escalations from the host against the same
volume:

```bash
podman run --rm -v atb-chain:/var/lib/atb --network=none ianua-atb \
  python -m atb.cli pending --chain /var/lib/atb/audit-chain.jsonl
```

> Note: run the operator CLI while the gateway is idle — the chain has one
> writer at a time by design.

macOS note: podman runs containers in a Linux VM (`podman machine`); this is
fine for development, but the deployment target is the Linux lab host.
