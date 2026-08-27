# Signer & KES Agent Packaging

Deployment artifacts for `bursa signer` and `bursa kes-agent`. Operator docs are
in [`docs/signer/`](../../docs/signer/).

## Contents

| File | Purpose |
|------|---------|
| `bursa-signer.service` | systemd unit for the signer |
| `bursa-kes-agent.service` | systemd unit for the KES agent |
| `signer.env.example` | `EnvironmentFile` example (secrets) for the signer |
| `kes-agent.env.example` | `EnvironmentFile` example for the KES agent |
| `Dockerfile` | Container image for both daemons |

Both daemons are subcommands of the single `bursa` binary; the container image
and packaging cover both.

## systemd install

```sh
# Binary
install -m 0755 bursa /usr/bin/bursa

# Service users and groups (create the group explicitly; do not rely on a
# distro's useradd defaulting to a same-named private group)
groupadd --system bursa-signer
useradd --system --no-create-home --shell /usr/sbin/nologin -g bursa-signer bursa-signer
groupadd --system bursa-kes-agent
useradd --system --no-create-home --shell /usr/sbin/nologin -g bursa-kes-agent bursa-kes-agent

# Config (0600 secrets, 0700 dirs, owned by the service user)
install -d -o bursa-signer -g bursa-signer -m 0700 /etc/bursa/signer
install -m 0600 -o bursa-signer -g bursa-signer signer.env.example /etc/bursa/signer/signer.env
# ...install signer.yaml and TLS material alongside...

# Units
install -m 0644 bursa-signer.service bursa-kes-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now bursa-signer.service
```

Validate a unit before enabling:

```sh
systemd-analyze verify /etc/systemd/system/bursa-signer.service
```

## Hardening

Both units apply `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`/`PrivateDevices`, kernel/cgroup protections, a `@system-service`
syscall filter, and `MemoryDenyWriteExecute=true` (the Go runtime needs no
W+X memory). Each runs as its own unprivileged user. Writable state is confined
to a `StateDirectory` (watermark SQLite for the signer, the KES period guard
file for the agent).

The KES agent additionally sets `LimitMEMLOCK=64MiB` because it holds the KES
signing key in `mlock`'d memory; without a sufficient memlock limit the lock
fails.

## Socket permissions (KES agent)

The KES agent creates two Unix sockets, owned by `bursa-kes-agent`, under the
unit's `RuntimeDirectory` (`/run/bursa/kes-agent`, mode `0710`):

- `service.sock` - the block producer connects here. Mode
  `service_socket_mode` (default `0600`).
- `control.sock` - operator key management (`gen-staged-key`, `install-key`,
  `drop-key`, `info`). Mode `control_socket_mode` (default `0600`, always
  operator-only - see below).

Access is enforced purely by filesystem permissions, so:

- Never expose these over a network. They are local Unix sockets only.
- To let the block producer reach the service socket, either add the
  producer's user to the `bursa-kes-agent` group and set
  `kes_agent.service_socket_mode: "0660"`, or run producer and agent under a
  shared group. The client also needs execute (search) permission on
  `/run/bursa/kes-agent` and every parent directory, not merely read access.
- `service_socket_mode` and `control_socket_mode` are independent settings.
  Do **not** widen `control_socket_mode` to grant the producer group access -
  it can drop/install keys and must stay restricted to operators (owner-only
  `0600`, never shared with the producer's group).

## Container

See the header of [`Dockerfile`](Dockerfile) for build and run commands. Mount
config read-only, pass secrets via environment variables, and for the KES agent
share the socket directory with the producer and raise the memlock ulimit
(`--ulimit memlock=67108864:67108864`).

The image runs as non-root UID 65532. Mount a writable volume for any
persistent state and point the relevant config field at a path inside it: the
KES agent's `kes_agent.guard_file` (env `KESAGENT_GUARD_FILE`), and the
signer's watermark database when using the `file` (SQLite) watermark type
(`signer.watermark.path`, no env override - set it in the mounted config).
The KES agent refuses to start when `guard_file` is empty.
Without a mounted volume, that state lives only in the container's writable
layer and is lost when the container is removed - equivalent to the
`StateDirectory` the systemd units provision on bare metal.
