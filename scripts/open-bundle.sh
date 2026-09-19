#!/bin/sh
# Independent URMA V0 decoder: POSIX shell/utilities + OpenSSL 3. No URMA executable.
# Experimental, offline, trusted single-user machine only. OpenSSL CLI receives
# per-object derived keys in argv; do not expose process arguments or run as a service.
# This decodes an offline bundle, NOT Bitcoin/Litecoin blocks or inclusion proofs.
set +x
set -efu
LC_ALL=C
export LC_ALL
umask 077

fail() { printf '%s\n' "error: $*" >&2; exit 1; }
[ "$#" -eq 3 ] || [ "$#" -eq 4 ] || fail 'usage: sh open-bundle.sh ROOT_FILE CONTAINER_FILE NEW_OUTPUT_FILE [MAX_RECORDS]'
# Explicit local capacity; it does not change the canonical u32 chunk bound.
urma_capacity=${4:-512}
case $urma_capacity in ''|*[!0-9]*) fail 'invalid record capacity' ;; esac
[ "$urma_capacity" -ge 1 ] && [ "$urma_capacity" -le 4294967295 ] || fail 'invalid record capacity'
urma_max_size=$((12 + urma_capacity * 32932))
case $1 in /*) urma_key=$1 ;; *) urma_key=$PWD/$1 ;; esac
case $2 in /*) urma_input=$2 ;; *) urma_input=$PWD/$2 ;; esac
case $3 in /*) urma_output=$3 ;; *) urma_output=$PWD/$3 ;; esac
[ -f "$urma_key" ] && [ -f "$urma_input" ] || fail 'key and bundle must be regular files'
case $(ls -ld "$urma_key") in -???------*) ;; *) fail 'key must be a private regular file (chmod 600)' ;; esac
[ ! -e "$urma_output" ] && [ ! -L "$urma_output" ] || fail 'output already exists'
urma_parent=${urma_output%/*}
[ -d "$urma_parent" ] || fail 'output parent does not exist'
case $(openssl version) in 'OpenSSL 3.'*) ;; *) fail 'OpenSSL 3 is required' ;; esac
[ "$(wc -c < "$urma_key" | tr -d ' ')" -eq 32 ] || fail 'key must contain exactly 32 raw bytes'

# Exclusive private directory on the output filesystem; no non-POSIX mktemp.
urma_random=$(openssl rand -hex 16) || fail 'temporary name generation failed'
case $urma_random in ''|*[!0-9a-f]*) fail 'invalid temporary name' ;; esac
urma_work=$urma_parent/.urma-open-$urma_random
mkdir "$urma_work" || fail 'cannot create private workspace'
cleanup() {
    set +f
    rm -f "$urma_work/bundle" "$urma_work/record" "$urma_work/slice" \
        "$urma_work/numbers" "$urma_work/derived" "$urma_work/authenticated" \
        "$urma_work/mac" "$urma_work/body" "$urma_work/chunk" "$urma_work/result" \
        "$urma_work/digest"
    rm -f "$urma_work"/chunk.* "$urma_work"/record.*
    rmdir "$urma_work"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

# Bounded private snapshot with one extra block to detect capacity overflow.
urma_snapshot_blocks=$((urma_max_size / 4096 + 1))
dd if="$urma_input" of="$urma_work/bundle" bs=4096 count="$urma_snapshot_blocks" 2>/dev/null || fail 'cannot snapshot container'
urma_size=$(wc -c < "$urma_work/bundle" | tr -d ' ')
[ "$urma_size" -ge 12 ] && [ "$urma_size" -le "$urma_max_size" ] || fail 'container exceeds client capacity'

slice() {
    dd if="$1" of="$urma_work/slice" bs=1 skip="$2" count="$3" 2>/dev/null || fail 'read failed'
    [ "$(wc -c < "$urma_work/slice" | tr -d ' ')" -eq "$3" ] || fail 'truncated data'
}
hex_file() {
    od -An -v -tx1 "$1" > "$urma_work/numbers" || fail 'hex conversion failed'
    tr -d ' \n' < "$urma_work/numbers"
}
hex_at() { slice "$1" "$2" "$3"; hex_file "$urma_work/slice"; }
uint_at() {
    slice "$1" "$2" "$3"
    od -An -v -tu1 "$urma_work/slice" > "$urma_work/numbers" || fail 'integer conversion failed'
    # Check bounds before passing even a u64 to shell arithmetic.
    awk -v maximum="$4" 'BEGIN { n=0; m=1 } { for(i=1;i<=NF;i++) { n+=$i*m; m*=256 } }
        END { if(n>maximum) exit 1; printf "%.0f", n }' "$urma_work/numbers"
}
derive() {
    openssl kdf -keylen "$2" -kdfopt digest:SHA256 -kdfopt mode:EXPAND_ONLY \
        -kdfopt "hexkey:$urma_prk" \
        -kdfopt "info:URMA/V0/private/$1" -binary \
        -out "$urma_work/derived" HKDF || fail 'key derivation failed'
    hex_file "$urma_work/derived"
}

[ "$(hex_at "$urma_work/bundle" 0 8)" = 55524d4100030000 ] || fail 'unsupported bundle version'
urma_records=$(uint_at "$urma_work/bundle" 8 4 "$urma_capacity") || fail 'invalid bundle count'
[ "$urma_records" -gt 0 ] || fail 'empty bundle'
[ "$urma_size" -eq "$((12 + urma_records * 32932))" ] || fail 'truncated or trailing bundle data'
urma_id=
urma_seen=0
urma_record_n=0
while [ "$urma_record_n" -lt "$urma_records" ]; do
    urma_offset=$((12 + urma_record_n * 32932))
    urma_length=$(uint_at "$urma_work/bundle" "$urma_offset" 4 32928) || fail 'invalid record size'
    [ "$urma_length" -eq 32928 ] || fail 'invalid record size'
    slice "$urma_work/bundle" "$((urma_offset + 4))" 32928
    mv "$urma_work/slice" "$urma_work/record"
    [ "$(hex_at "$urma_work/record" 0 8)" = 55524d4100010000 ] || fail 'unsupported record version'
    urma_record_id=$(hex_at "$urma_work/record" 8 32)
    if [ -z "$urma_id" ]; then
        urma_id=$urma_record_id
        # HKDF-Extract: public salt is the HMAC key; the media root is read as
        # binary input, never placed in shell variables or process arguments.
        openssl mac -digest SHA256 -macopt "hexkey:$urma_id" -in "$urma_key" \
            -binary -out "$urma_work/derived" HMAC || fail 'key extraction failed'
        urma_prk=$(hex_file "$urma_work/derived")
        urma_discovery=$(derive discovery 16)
        urma_encryption=$(derive content 32)
        urma_authentication=$(derive authentication 32)
    fi
    [ "$urma_record_id" = "$urma_id" ] || fail 'mixed objects'
    [ "$(hex_at "$urma_work/record" 40 16)" = "$urma_discovery" ] || fail 'wrong key or unrelated record'
    urma_index=$(uint_at "$urma_work/record" 56 4 4294967294) || fail 'invalid chunk index'
    urma_count=$(uint_at "$urma_work/record" 60 4 4294967295) || fail 'invalid chunk count'
    [ "$urma_index" -lt "$urma_count" ] || fail 'invalid chunk bounds'

    slice "$urma_work/record" 0 32896
    mv "$urma_work/slice" "$urma_work/authenticated"
    openssl mac -digest SHA256 -macopt "hexkey:$urma_authentication" \
        -in "$urma_work/authenticated" -binary -out "$urma_work/mac" HMAC || fail 'MAC operation failed'
    urma_actual_mac=$(hex_file "$urma_work/mac")
    urma_expected_mac=$(hex_at "$urma_work/record" 32896 32)
    # Offline comparison only; shell does not promise constant-time execution.
    [ "$urma_actual_mac" = "$urma_expected_mac" ] || fail 'record authentication failed'
    urma_iv=$(hex_at "$urma_work/record" 64 16)
    urma_canonical_iv=$(printf '%016x0000000000000000' "$urma_index")
    [ "$urma_iv" = "$urma_canonical_iv" ] || fail 'noncanonical counter IV'

    # Never decrypt anything until its complete header/IV/ciphertext MAC passes.
    slice "$urma_work/record" 80 32816
    openssl enc -d -aes-256-ctr -nosalt -K "$urma_encryption" -iv "$urma_iv" \
        -in "$urma_work/slice" -out "$urma_work/body" || fail 'decryption failed'
    urma_total=$(uint_at "$urma_work/body" 32 8 140737488322560) || fail 'invalid encrypted length'
    [ "$urma_total" -gt 0 ] && [ "$(((urma_total + 32767) / 32768))" -eq "$urma_count" ] || fail 'length/count mismatch'
    urma_type=$(uint_at "$urma_work/body" 40 4 4) || fail 'unsupported content type'
    [ "$(hex_at "$urma_work/body" 44 4)" = 00000000 ] || fail 'unsupported metadata flags'
    urma_digest=$(hex_at "$urma_work/body" 0 32)
    if [ "$urma_record_n" -eq 0 ]; then
        urma_expected_total=$urma_total
        urma_expected_count=$urma_count
        urma_expected_digest=$urma_digest
        urma_expected_type=$urma_type
    fi
    [ "$urma_total" -eq "$urma_expected_total" ] && \
        [ "$urma_count" -eq "$urma_expected_count" ] && \
        [ "$urma_digest" = "$urma_expected_digest" ] && \
        [ "$urma_type" -eq "$urma_expected_type" ] || fail 'conflicting authenticated metadata'
    urma_chunk_size=$((urma_total - urma_index * 32768))
    if [ "$urma_chunk_size" -gt 32768 ]; then urma_chunk_size=32768; fi
    slice "$urma_work/body" 48 "$urma_chunk_size"
    mv "$urma_work/slice" "$urma_work/chunk"
    if [ -f "$urma_work/chunk.$urma_index" ]; then
        cmp -s "$urma_work/record" "$urma_work/record.$urma_index" || fail 'conflicting duplicate'
    else
        mv "$urma_work/chunk" "$urma_work/chunk.$urma_index"
        mv "$urma_work/record" "$urma_work/record.$urma_index"
        urma_seen=$((urma_seen + 1))
    fi
    urma_record_n=$((urma_record_n + 1))
done
[ "$urma_seen" -eq "$urma_expected_count" ] || fail 'missing chunks'
: > "$urma_work/result"
urma_index=0
while [ "$urma_index" -lt "$urma_expected_count" ]; do
    cat "$urma_work/chunk.$urma_index" >> "$urma_work/result" || fail 'assembly failed'
    urma_index=$((urma_index + 1))
done
[ "$(wc -c < "$urma_work/result" | tr -d ' ')" -eq "$urma_expected_total" ] || fail 'reassembled length mismatch'
openssl dgst -sha256 -binary -out "$urma_work/digest" "$urma_work/result" || fail 'hash failed'
[ "$(hex_file "$urma_work/digest")" = "$urma_expected_digest" ] || fail 'whole-file integrity failed'

# Atomic no-clobber publication in a trusted output parent on the same filesystem.
[ ! -e "$urma_output" ] && [ ! -L "$urma_output" ] || fail 'output already exists'
ln "$urma_work/result" "$urma_output" || fail 'cannot publish output without overwrite'
unset urma_prk urma_encryption urma_authentication
printf 'complete object=%s bytes=%s sha256=%s\n' "$urma_id" "$urma_expected_total" "$urma_expected_digest"
