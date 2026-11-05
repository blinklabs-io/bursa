# USB armory firmware

Signing, provisioning and wipe firmware for the USB armory Mk II. Build it on
a host with the TamaGo toolchain, `arm-none-eabi-objcopy` and `mkimage`:

```
source ~/tamago/env.sh
make imx                                  # signing image, unsigned
make imx PROVISION=1                      # provisioning image
make imx WIPE=1                           # wipe image
make imx NETWORK=mainnet CHAIN=cardano    # mainnet signing image
make imx NETWORK=multi                    # multi image: testnet, cardano-mainnet, prime-mainnet
make imx NETWORK=multi PROVISION=1        # its provisioning image (also WIPE=1)
make imx TESTNET=1                        # bring-up image, unfiltered /sign
```

The Makefile header documents each variable.

### Multi image

`NETWORK=multi` builds one image that serves three scopes: every testnet
(network id 0), `cardano-mainnet` and `prime-mainnet` (network id 1; profile
names end in `@cardano-mainnet` or `@prime-mainnet`). It builds as
`armory-multi`, `armory-provision-multi` and `armory-wipe-multi`. `CHAIN` does
not apply, and `TESTNET=1` is refused: a multi image serves mainnet scopes and
no unfiltered `/sign`. The single-scope images build as before.

- Every request needs a host key registered for the scope of the profile it
  acts on, testnet profiles included: signing, inventory, floor, reward, pins,
  profile provisioning and profile wipes. A testnet key never signs or
  provisions for a mainnet profile, nor a cardano-mainnet key for a
  prime-mainnet one. A key registered by an older, unscoped image counts as a
  testnet key. A new testnet profile may not take a name ending
  `@cardano-mainnet` or `@prime-mainnet`.
- The device's first host key is added unsigned, by the `PROVISION=1` image
  only, while the device holds no host key, with `scope` naming a scope of
  the image; register a mainnet scope's key first. A key of a mainnet scope
  then adds the first key of each other scope. The signing and wipe images
  never take an unsigned request. A signed host key add names the scope, and
  the key that signs it is of that scope, or of a mainnet scope while the
  scope has no key.
- `/provision/identity`, `/wipe/signlog`, the signing log read, listing the
  keys of other scopes and revoking one need a key of a mainnet scope. A key
  revokes keys of its own scope, its last one included unless it is the
  device's last key, which only a device wipe removes; a mainnet key does
  not revoke the last key of another scope.
- A cold key, or an imported owner key, that belongs to a profile of another
  scope is refused; two slots of one scope may hold the same key.
- Any scope takes any free cold key object (32: `0x20e50010`-`0x20e5001f` and
  `0x20e50600`-`0x20e5060f`); it then belongs to that scope, recorded in the
  ownership object `0x20e50023`, and only that scope imports into it again or
  provisions a profile on it. Signing refuses a key the record gives to
  another scope; a record that cannot be read does not stop signing. An
  empty object is free whatever an old claim says. Every image keeps the
  record, single-scope images with their own scope. A key an older image
  stored with no claim belongs to the scope of the profiles on it; a key with
  no claim and no profile, or profiles of two scopes, belongs to no scope and
  is refused to all. A profile
  an older image stored is still served.
- The wipe image's signed `/wipe/cold` deletes a cold key no profile names,
  and its claim: its owner may, and a mainnet key may delete a testnet key or
  one with no owner, never the other mainnet scope's. A mainnet key also
  removes a testnet profile with `/wipe/profile`.
- Do not flash an image older than this one over a device it has used. An
  older image does not know the second cold key block or the ownership
  record: its `/wipe/device` leaves them on the chip, and it imports into an
  object another scope owns. Wipe with this image's wipe image first.
- A device that ran a testnet image keeps its profiles and host key. A
  testnet key does not act device-wide on the multi image and the device's
  last key cannot be revoked, so adding mainnet scopes takes a device wipe:
  wipe it, register a mainnet key unsigned with the provisioning image, and
  add the testnet key again with it.

`./hab_makefile_test.sh` dry-runs
the HAB targets below, and runs the signing step against a stub `habtool`; it
needs only `make`.

## Secure boot (HABv4)

The boot ROM runs any image it finds. On a board whose secure boot fuses are
burned it runs only images signed with the key whose hash is fused, from every
boot source (internal flash, memory card, USB recovery). The
[usbarmory secure boot guide](https://github.com/usbarmory/usbarmory/wiki/Secure-boot-(Mk-II))
describes the mechanism; `habtool` from
[crucible](https://github.com/usbarmory/crucible) makes the keys and signs.

This directory signs images. It does not fuse. Fusing is permanent and is a
separate, rehearsed procedure; nothing here writes OTP.

### Tools

```
go install github.com/usbarmory/crucible/cmd/habtool@v2025.05.28
```

`habtool` must be on `PATH`, or set `HABTOOL=<path>`. The flags used here
are those of crucible `v2025.05.28`.

### Keys

Make production keys on an offline machine, never on a host that builds or
serves anything, and keep them out of this checkout (`.gitignore` excludes
`*.pem` as a backstop, not a control).

```
(
set -e; umask 077
mkdir -m 0700 hab-keys; cd hab-keys
for i in 1 2 3 4; do habtool -C SRK_${i}_key.pem -c SRK_${i}_crt.pem; done
habtool -1 SRK_1_crt.pem -2 SRK_2_crt.pem -3 SRK_3_crt.pem -4 SRK_4_crt.pem \
        -t SRK_1_2_3_4_table.bin -o SRK_1_2_3_4_fuse.bin
habtool -C SRK_1_key.pem -c SRK_1_crt.pem \
        -A CSF_1_key.pem -a CSF_1_crt.pem \
        -B IMG_1_key.pem -b IMG_1_crt.pem
)
```

Run it in a fresh location: the subshell stops at the first failure, so an
existing `hab-keys` directory is never written into.

`SRK_1_2_3_4_fuse.bin` is the 32-byte hash that would be fused; it is public.
Back up the SRK private keys and the whole directory offline: a lost key
leaves a fused board unable to run new firmware. Use a throwaway directory for
unfused test boards and never fuse its hash.

### Signing

`HAB_KEYS` signs on the build host, so it is for keys that may live there,
such as throwaway keys for unfused test boards. With production keys, build
the unsigned image, copy it to the offline machine and sign it there with
`habtool`, as in "Signing offline" below; the build host never holds the
keys.

Set `HAB_KEYS` to the key directory. Every variant is signed, and the unsigned
image is still built:

```
make imx HAB_KEYS=/path/to/hab-keys                           # armory-signed.imx
make imx PROVISION=1 HAB_KEYS=...                             # armory-provision-signed.imx
make imx WIPE=1 HAB_KEYS=...                                  # armory-wipe-signed.imx
make imx NETWORK=mainnet CHAIN=cardano HAB_KEYS=...           # armory-cardano-mainnet-signed.imx
make imx NETWORK=multi HAB_KEYS=...                           # armory-multi-signed.imx
make imx HAB_SDP=1 HAB_KEYS=...                               # armory-signed-sdp.imx
```

The Makefile reads `CSF_1_*`, `IMG_1_*` and `SRK_1_2_3_4_table.bin` from
`HAB_KEYS`. `HAB_SRK_INDEX=<n>` (1 to 4, default 1) signs with SRK key n and
reads `CSF_<n>_*` and `IMG_<n>_*` instead, which must be certificates issued
by `SRK_<n>`, as the last key command does for SRK 1. The default
signature is for the internal flash and memory cards; `HAB_SDP=1` signs for
loading over USB in recovery mode, which clears the DCD pointer. Without
`HAB_KEYS` the build is unchanged.

A `TESTNET=1` image adds the bring-up key tests and an unfiltered `/sign`
endpoint. Signing it with a boot key makes it runnable on any board fused to
that key, so the Makefile refuses unless `HAB_ALLOW_TESTNET=1` is
given, and then warns and writes `armory-testnet-signed.imx`, a name the
signed signing image never takes. Use that only with a throwaway key on a
board holding no keys that matter.

### Signing offline

Copy the unsigned image to the offline machine and, with `K` the key
directory, sign it there the way the Makefile does:

```
habtool -A $K/CSF_1_key.pem -a $K/CSF_1_crt.pem -B $K/IMG_1_key.pem \
        -b $K/IMG_1_crt.pem -t $K/SRK_1_2_3_4_table.bin -x 1 \
        -i armory.imx -o armory-signed.csf
cat armory.imx armory-signed.csf > armory-signed.imx
```

Add `-s` to sign for USB recovery loading (as `HAB_SDP=1` does); without it
the image is signed for the internal flash and memory cards.

### Flashing image

Writing the internal flash uses the upstream `armory-ums` image, which this
repository does not build. The boot ROM checks it like any other image, so
sign it offline with the same key, for loading over USB:

```
habtool -A $K/CSF_1_key.pem -a $K/CSF_1_crt.pem -B $K/IMG_1_key.pem \
        -b $K/IMG_1_crt.pem -t $K/SRK_1_2_3_4_table.bin -x 1 -s \
        -i armory-ums.imx -o armory-ums.csf
cat armory-ums.imx armory-ums.csf > armory-ums-signed.imx
```

### Checking a signed image on an unfused board

`habtool` has no verify command. A signed image is the unsigned image followed
by its CSF: the IVT's CSF pointer must point at the end of the unsigned image,
where the byte `0xd4` (the CSF header tag) starts the CSF.

An unfused board is in the open configuration: the boot ROM runs a bad or
unsigned image anyway and records HAB events, so a signature failure does not
show as a refusal to boot. The events are read with the HAB `hab_status`
report (as in U-Boot's `hab_status` command). The firmware reads them at
boot, before the network and USB stack start, and adds the HAB status and
its events to the bring-up report served at `/`. On an unfused board, that
report is how to check that the boot ROM accepted a signed image.
