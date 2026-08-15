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
or a systemd/Quadlet unit.

## Resolving escalations

The chain has **one writer at a time** by design: appending from two
processes forks it, after which every open fails closed. So the operator
loop is *stop → resolve → restart* (the gateway replays the chain, including
the resolution, on startup; the agent's retry then consumes the approval):

```bash
podman stop atb-gateway
```

```bash
podman run --rm --entrypoint atb -v atb-chain:/var/lib/atb --network=none ianua-atb \
  pending --chain /var/lib/atb/audit-chain.jsonl
```

```bash
podman run --rm --entrypoint atb -v atb-chain:/var/lib/atb --network=none ianua-atb \
  approve ATB-DEC-000123 --approver "$USER" --reason "known safe intel feed" \
  --chain /var/lib/atb/audit-chain.jsonl
```

Then start the gateway again. (`--entrypoint atb` is required — the image's
default entrypoint is the gateway, and arguments appended without it would
just be ignored by the gateway process.)

macOS note: podman runs containers in a Linux VM (`podman machine`); this is
fine for development, but the deployment target is the Linux lab host.
