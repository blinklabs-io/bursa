# USB armory firmware

Signing, provisioning and wipe firmware for the USB armory Mk II. Build it on
a host with the TamaGo toolchain, `arm-none-eabi-objcopy` and `mkimage`:

```
source ~/tamago/env.sh
make imx                                  # signing image, unsigned
make imx PROVISION=1                      # provisioning image
make imx WIPE=1                           # wipe image
make imx NETWORK=mainnet CHAIN=cardano    # mainnet signing image
make imx TESTNET=1                        # bring-up image, unfiltered /sign
```

The Makefile header documents each variable. `./hab_makefile_test.sh` dry-runs
the HAB targets below and needs only `make`.

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
go install github.com/usbarmory/crucible/cmd/habtool@latest
```

`habtool` must be on `PATH`, or set `HABTOOL=<path>`.

### Keys

Make production keys on an offline machine, never on a host that builds or
serves anything, and keep them out of this checkout (`.gitignore` excludes
`*.pem` as a backstop, not a control).

```
umask 077; mkdir -m 0700 hab-keys; cd hab-keys
for i in 1 2 3 4; do habtool -C SRK_${i}_key.pem -c SRK_${i}_crt.pem; done
habtool -1 SRK_1_crt.pem -2 SRK_2_crt.pem -3 SRK_3_crt.pem -4 SRK_4_crt.pem \
        -t SRK_1_2_3_4_table.bin -o SRK_1_2_3_4_fuse.bin
habtool -C SRK_1_key.pem -c SRK_1_crt.pem \
        -A CSF_1_key.pem -a CSF_1_crt.pem \
        -B IMG_1_key.pem -b IMG_1_crt.pem
```

`SRK_1_2_3_4_fuse.bin` is the 32-byte hash that would be fused; it is public.
Back up the SRK private keys and the whole directory offline: a lost key
leaves a fused board unable to run new firmware. Use a throwaway directory for
unfused test boards and never fuse its hash.

### Signing

Set `HAB_KEYS` to the key directory. Every variant is signed, and the unsigned
image is still built:

```
make imx HAB_KEYS=/path/to/hab-keys                           # armory-signed.imx
make imx PROVISION=1 HAB_KEYS=...                             # armory-provision-signed.imx
make imx WIPE=1 HAB_KEYS=...                                  # armory-wipe-signed.imx
make imx NETWORK=mainnet CHAIN=cardano HAB_KEYS=...           # armory-cardano-mainnet-signed.imx
make imx HAB_SDP=1 HAB_KEYS=...                               # armory-signed-sdp.imx
```

The Makefile reads `CSF_1_*`, `IMG_1_*` and `SRK_1_2_3_4_table.bin` from
`HAB_KEYS`; `HAB_SRK_INDEX` selects another SRK key (default 1). The default
signature is for the internal flash and memory cards; `HAB_SDP=1` signs for
loading over USB in recovery mode, which clears the DCD pointer. Without
`HAB_KEYS` the build is unchanged.

A `TESTNET=1` image serves an unfiltered `/sign` endpoint that signs with the
first cold key slot. Signing it with a boot key makes it runnable on any board
fused to that key, so the Makefile refuses unless `HAB_ALLOW_TESTNET=1` is
given, and then warns. Use that only with a throwaway key on a board holding
no keys that matter.

### Flashing image

Writing the internal flash uses the upstream `armory-ums` image, which this
repository does not build. The boot ROM checks it like any other image, so
sign it with the same key before loading it over USB:

```
habtool -A $K/CSF_1_key.pem -a $K/CSF_1_crt.pem -B $K/IMG_1_key.pem \
        -b $K/IMG_1_crt.pem -t $K/SRK_1_2_3_4_table.bin -x 1 -s \
        -i armory-ums.imx -o armory-ums.csf
cat armory-ums.imx armory-ums.csf > armory-ums-signed.imx
```

`-s` is for USB recovery loading (as for `HAB_SDP=1`); omit it for an image
that is booted from a card.

### Checking a signed image on an unfused board

`habtool` has no verify command. A signed image is the unsigned image followed
by its CSF: the IVT's CSF pointer must point at the end of the unsigned image,
where the byte `0xd4` (the CSF header tag) starts the CSF.

An unfused board is in the open configuration: the boot ROM runs a bad or
unsigned image anyway and records HAB events, so a signature failure does not
show as a refusal to boot. The events are read with the HAB `hab_status`
report (as in U-Boot's `hab_status` command). Neither TamaGo nor this
firmware reads them yet, so that reading, and the bring-up report that
includes it, is follow-up work. Until it exists, signed images are checked on
an unfused board only by their structure; the first test that the boot ROM
accepts them needs a board and the HAB event report.
