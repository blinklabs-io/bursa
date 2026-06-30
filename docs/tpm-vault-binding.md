# TPM Vault Binding

The full-node wallet supports optionally binding the at-rest vault to the TPM
(Trusted Platform Module) of the machine it runs on. This is a desktop/server
feature; it is not available on mobile.

## What it protects

TPM binding seals the vault's Vault Encryption Key (VEK) to the local TPM 2.0
device. With binding enabled, the TPM-wrapped copy of the vault key can only be
unsealed by that TPM, but the password protector remains on disk as the
universal recovery path. A copied vault can still be opened on another machine
with the vault password, so losing the TPM (hardware failure, machine loss) or
disabling it never bricks the vault.

**TPM binding does NOT protect the signing key.** The spending password and the
per-wallet seed encryption are entirely separate. TPM binding is about
machine-binding of the at-rest vault index, not key custody.

## Enabling TPM binding

In the wallet settings UI, the "Hardware security" card shows the TPM status.
If a TPM 2.0 device is found, click "Enable TPM binding" and enter your vault
password. This re-wraps the VEK under the TPM and persists both protectors
(password + TPM) on disk.

Via the API:

```
POST /vault/tpm/enable
{ "password": "<vault-password>", "pcrBound": false }
```

## PCR binding (advanced)

The optional **PCR binding** flag additionally ties the seal to the current
boot state (PCR 7 — Secure Boot policy). This means the vault key can only be
unsealed when the boot firmware matches the state at enrollment time.

**PCR binding is brittle.** A firmware update, Secure Boot key rotation, or
boot-loader change will invalidate the PCR measurement and prevent TPM
unsealing. When this happens, the vault remains accessible via the vault
password (the password protector is always kept), but you will need to
re-enroll the TPM after updating firmware.

Only enable PCR binding if you understand and accept this trade-off.

## Disabling TPM binding

```
POST /vault/tpm/disable
{ "password": "<vault-password>" }
```

Disabling removes the TPM protector and re-persists with the password protector
only. The VEK is unchanged; only the key section is re-written.

## Linux: tss group permissions

On Linux, `/dev/tpm0` and `/dev/tpmrm0` are owned by root and the `tss`
group. The wallet process must be a member of the `tss` group to access the
TPM:

```sh
sudo usermod -aG tss <your-user>
# log out and back in for the group change to take effect
```

If the TPM is present but the process lacks permission, the status endpoint
returns `available: false` with a reason such as `"permission denied: add your user to the tss group"`.

## Platform availability

TPM binding is supported on Linux and Windows with a TPM 2.0 device. It is
**not available on mobile** (Android/iOS) because those platforms do not
expose a TPM 2.0 interface to userspace applications. The mobile build compiles
the TPM code with a no-op stub that always reports unavailable.

## API reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/vault/tpm/status` | Probe TPM availability + enrollment state. No vault unlock needed. |
| `POST` | `/vault/tpm/enable` | Add TPM protector. Body: `{ password, pcrBound? }`. Authenticates via vault password. |
| `POST` | `/vault/tpm/disable` | Remove TPM protector; password-only vault restored. Body: `{ password }`. |

Status response:

```json
{
  "available": true,
  "reason": "",
  "enabled": true,
  "pcrBound": false
}
```

`reason` is a human-readable explanation when `available` is `false`.
