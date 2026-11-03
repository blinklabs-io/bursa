#!/usr/bin/env bash
# Copyright 2026 Blink Labs Software
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Runs preview-pool-registration.sh against stub bursa, armory-pool, curl,
# armory-boot-usb and sleep (no node, no device) from a work directory left by
# an earlier run, so it goes straight to the signing image check, and checks
# how the script waits for the signing log card:
#   * device on the signing image: no answer, unfinished startup, no signing
#     log line and a log that is not open each fail with their own message; an
#     open log lets the run continue to the device inventory
#   * device on the provisioning image: without SIGNING_IMX, or without a
#     terminal, the script fails before it resets the board; with a terminal it
#     resets, waits for Enter before it loads the signing image, and then checks
#     the signing log
#
# Needs python3 for the terminal case, and setsid.
#
# Usage: bash armory/e2e/preview-pool-registration-log-card-test.sh [script]

set -euo pipefail

SCRIPT=$(realpath "${1:-$(dirname "$0")/preview-pool-registration.sh}")
T=$(mktemp -d -t pool-e2e-log-card-XXXXXX)
trap 'rm -rf "$T"' EXIT
mkdir "$T/bin"

POOL_ID=$(printf 'ab%.0s' $(seq 28))
PUB_HEX=$(printf '11%.0s' $(seq 32))
IMX=$T/signing.imx

cat > "$T/bin/bursa" << 'STUB'
#!/usr/bin/env bash
case "$1 $2" in
"query tip") echo '{"era":"Conway","epoch":1}' ;;
"query utxo") echo '[{"amount":99000000000}]' ;;
"query stake-address") echo '{"registered":true}' ;;
*) echo "unexpected bursa $*" >&2; exit 99 ;;
esac
STUB

# the device inventory is the first step after the signing image check
cat > "$T/bin/armory-pool" << STUB
#!/usr/bin/env bash
case \$1 in
address) echo stake_test1stub; exit 0 ;;
reward-hex) echo e0aa; exit 0 ;;
esac
for a in "\$@"; do [ "\$a" = keys ] && { touch "$T/keys.reached"; exit 42; }; done
echo "unexpected armory-pool \$*" >&2
exit 99
STUB

cat > "$T/bin/sleep" << 'STUB'
#!/usr/bin/env bash
:
STUB

cat > "$T/bin/armory-boot-usb" << STUB
#!/usr/bin/env bash
echo "boot \$*" >> "$T/events"
echo signing > "$T/device"
STUB

# $T/device holds the running image. Every GET of the bring-up report is
# counted; STUB_REPORT picks what the signing image reports:
#   none      answers the first STUB_GETS requests, then nothing answers
#   starting  bring-up has not reported its RESULT line yet
#   nolog     no signing log line
#   notopen   the log card was missing when the image started
#   open      the signing log is open
cat > "$T/bin/curl" << STUB
#!/usr/bin/env bash
case "\$*" in
*/reset*) echo reset >> "$T/events"; exit 0 ;;
*POST*) echo "unexpected curl \$*" >&2; exit 99 ;;
esac
n=\$((\$(cat "$T/gets" 2> /dev/null || echo 0) + 1))
echo "\$n" > "$T/gets"
if [ "\$(cat "$T/device")" = provisioning ]; then
	printf '%s\n' "provisioning build: signing endpoints are not served" \
		"signing log: not used by the provisioning image" "RESULT: PASS"
	exit 0
fi
b="signing build: provisioning endpoints are not served"
open="signing log: open on a 1024-block card, head entry 0 00"
case \$STUB_REPORT in
none) [ "\$n" -le "\$STUB_GETS" ] || exit 7; printf '%s\n' "\$b" "\$open" "RESULT: PASS" ;;
starting) printf '%s\n' "\$b" "\$open" ;;
nolog) printf '%s\n' "\$b" "RESULT: PASS" ;;
notopen) printf '%s\n' "\$b" "signing log: NOT OPEN, signing is refused: no card" "RESULT: FAIL" ;;
open) printf '%s\n' "\$b" "\$open" "RESULT: PASS" ;;
*) echo "unexpected STUB_REPORT \$STUB_REPORT" >&2; exit 99 ;;
esac
STUB
chmod +x "$T/bin/"*

# enter.py OUT CMD...: runs CMD with a pty as its controlling terminal and its
# output in OUT. A second after the Enter prompt appears on the terminal it
# copies the event log to $T/events.at-prompt, then presses Enter.
cat > "$T/enter.py" << STUB
import os, pty, select, shutil, sys, time
out, cmd = sys.argv[1], sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    o = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.dup2(o, 1)
    os.dup2(o, 2)
    os.execvp(cmd[0], cmd)
seen, answered, status, deadline = b"", False, None, time.time() + 30
while time.time() < deadline:
    p, st = os.waitpid(pid, os.WNOHANG)
    if p:
        status = st
        break
    if select.select([fd], [], [], 0.2)[0]:
        try:
            seen += os.read(fd, 1024)
        except OSError:
            time.sleep(0.05)
    if not answered and b"press Enter" in seen:
        # a script that does not wait for Enter loads the image in this time
        time.sleep(1)
        if os.path.exists("$T/events"):
            shutil.copy("$T/events", "$T/events.at-prompt")
        else:
            open("$T/events.at-prompt", "w").close()
        os.write(fd, b"\n")
        answered = True
if status is None:
    os.kill(pid, 9)
    status = os.waitpid(pid, 0)[1]
sys.exit(os.waitstatus_to_exitcode(status))
STUB

problems=0
bad() { echo "FAIL: $*"; problems=$((problems + 1)); }

# run NAME DEVICE [ENV...]: run the script from a fresh work directory left by
# an earlier run (keys derived, cold key imported, profile provisioned), with
# the device on the DEVICE image; leaves the exit code in $rc. RUNNER, when
# set, is a command prefix that starts the script.
run() {
	local name=$1 device=$2 work=$T/work-$1
	shift 2
	rm -f "$T/events" "$T/events.at-prompt" "$T/gets" "$T/keys.reached"
	echo "$device" > "$T/device"
	mkdir -p "$work/pool"
	echo "seed words" > "$work/pool/seed.txt"
	printf '{"type":"X","description":"","cborHex":"5820%s"}\n' "$PUB_HEX" > "$work/pool-cold.vkey"
	for f in vrf.skey kes.skey reward.skey reward.vkey; do
		echo '{"type":"X","description":"","cborHex":"5820aa"}' > "$work/$f"
	done
	printf '{"pool_id":"%s","public_key":"%s"}\n' "$POOL_ID" "$PUB_HEX" > "$work/cold.json"
	printf '{"owner_key_hash":"%s","owner_public_key":""}\n' "$POOL_ID" > "$work/profile.json"
	rc=0
	env -u HOST_KEY -u SIGNING_IMX -u ARMORY_BOOT -u OPCERT_CHECK -u SIGNER -u SOURCE \
		STUB_REPORT=open STUB_GETS=0 "$@" \
		PATH="$T/bin:$PATH" WORK="$work" SOCKET=/dev/null PAYER_SKEY=/dev/null PAYER_VKEY=/dev/null \
		PAYER_ADDR=addr_test1stub IDENTITY=00 COLD_KEY_ID=551878672 SLOT=0 \
		${RUNNER:-} bash "$SCRIPT" > "$T/$name.out" 2>&1 || rc=$?
}

# expect NAME RC [TEXT]: the run exited with RC and its output has TEXT
expect() {
	local name=$1 want=$2 text=${3:-}
	[ "$rc" -eq "$want" ] || bad "$name: exit $rc, want $want"
	if [ -n "$text" ] && ! grep -qF -- "$text" "$T/$name.out"; then
		bad "$name: output lacks: $text"
	fi
	if [ "$want" -eq 42 ]; then
		[ -e "$T/keys.reached" ] || bad "$name: did not reach the device inventory"
	else
		[ ! -e "$T/keys.reached" ] || bad "$name: reached the device inventory"
	fi
}

# events NAME FILE WANT: the event log FILE holds exactly WANT
events() {
	local got
	got=$(cat "$2" 2> /dev/null || true)
	[ "$got" = "$3" ] || bad "$1: events [${got//$'\n'/; }], want [${3//$'\n'/; }]"
}

# the device already runs the signing image
run open signing STUB_REPORT=open
expect open 42
run none signing STUB_REPORT=none STUB_GETS=2
expect none 1 "FAIL the signing image did not answer at http://10.0.0.1"
run starting signing STUB_REPORT=starting
expect starting 1 "FAIL the signing image did not finish starting"
run nolog signing STUB_REPORT=nolog
expect nolog 1 "FAIL the signing image has no signing log (no signing log line)"
run notopen signing STUB_REPORT=notopen
expect notopen 1 "FAIL the signing image has no signing log (signing log: NOT OPEN"
events notopen "$T/events" ""

# the device runs the provisioning image
run no-imx provisioning
expect no-imx 1 "FAIL device runs the provisioning image; set SIGNING_IMX"
events no-imx "$T/events" ""

RUNNER="setsid -w" run no-tty provisioning SIGNING_IMX="$IMX" ARMORY_BOOT="$T/bin/armory-boot-usb"
expect no-tty 1 "FAIL no terminal to wait for the signing log card"
events no-tty "$T/events" ""

RUNNER="python3 -I $T/enter.py $T/tty-open.inner" run tty-open provisioning \
	SIGNING_IMX="$IMX" ARMORY_BOOT="$T/bin/armory-boot-usb" STUB_REPORT=open
cat "$T/tty-open.inner" >> "$T/tty-open.out" 2> /dev/null || true
expect tty-open 42 "PASS signing image loaded with its signing log"
[ -e "$T/events.at-prompt" ] || bad "tty-open: no Enter prompt on the terminal"
events tty-open "$T/events.at-prompt" "reset"
events tty-open "$T/events" "reset
boot -i $IMX"

RUNNER="python3 -I $T/enter.py $T/tty-notopen.inner" run tty-notopen provisioning \
	SIGNING_IMX="$IMX" ARMORY_BOOT="$T/bin/armory-boot-usb" STUB_REPORT=notopen
cat "$T/tty-notopen.inner" >> "$T/tty-notopen.out" 2> /dev/null || true
expect tty-notopen 1 "FAIL the signing image has no signing log (signing log: NOT OPEN"
events tty-notopen "$T/events" "reset
boot -i $IMX"

if [ "$problems" -ne 0 ]; then
	for f in "$T"/*.out; do
		echo "---- $(basename "$f" .out)"
		cat "$f"
	done
	exit 1
fi
echo "ok"
