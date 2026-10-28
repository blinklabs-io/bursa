#!/bin/sh

set -eu

umask 077

CDPATH=
export CDPATH
script_dir=$(cd "$(dirname "$0")" && pwd)
dev_dir=$(mktemp -d "${TMPDIR:-/tmp}/bursa-signer.XXXXXX")
cleanup_dir=$dev_dir
trap 'rm -rf "$cleanup_dir"' HUP INT TERM 0

keys_dir=$dev_dir/keys
config_file=$dev_dir/signer.yaml
auth_file=$dev_dir/auth.env

mkdir "$keys_dir"
cp "$script_dir/signer.example.yaml" "$config_file"
auth_secret=$(openssl rand -hex 32)
printf 'SIGNER_JWT_SECRET=%s\n' "$auth_secret" > "$auth_file"
unset auth_secret

chmod 700 "$dev_dir" "$keys_dir"
chmod 600 "$config_file" "$auth_file"

trap - HUP INT TERM 0
printf '%s\n' "$dev_dir"
