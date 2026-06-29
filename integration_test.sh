#!/bin/bash

set -e

ZERODRIVE_BIN="./target/debug/zerodrive"
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
TEST_DIR=$(mktemp -d -t zerodrive-test-XXXXXX)
FAKE_HOME="$TEST_DIR/home"
BLOB_DIR="$TEST_DIR/blobs"

mkdir -p "$FAKE_HOME"
export HOME="$FAKE_HOME"

pass() {
    echo -e "\033[1;32m✓ PASS:\033[0m $1"
}

fail() {
    echo -e "\033[1;31m✗ FAIL:\033[0m $1"
    cleanup
    exit 1
}

info() {
    echo -e "\033[1;34m• INFO:\033[0m $1"
}

run_zd() {
    echo "$MNEMONIC" | "$ZERODRIVE_BIN" --blob-dir "$BLOB_DIR" "$@"
}

cleanup() {
    info "Cleaning up test environment..."
    echo "$MNEMONIC" | "$ZERODRIVE_BIN" --blob-dir "$BLOB_DIR" stop >/dev/null 2>&1 || true
    sleep 1
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT INT TERM

if [ ! -f "$ZERODRIVE_BIN" ]; then
    fail "Binary not found at $ZERODRIVE_BIN. Please run 'cargo build' first."
fi

info "Starting integration tests in isolated environment: $TEST_DIR"

info "Test 1: Checking daemon status (should auto-spawn)..."
OUTPUT=$(run_zd status 2>&1) || fail "Status command failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Daemon running" || fail "Daemon did not report running status."
pass "Daemon auto-spawned and is running."

info "Waiting 3 seconds for Nostr relay connections to establish..."
sleep 3

info "Test 2: Creating drive 'test-drive'..."
OUTPUT=$(run_zd create-drive test-drive 2>&1) || fail "Create drive failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Drive 'test-drive' created" || fail "Drive creation output mismatch."
pass "Drive 'test-drive' created successfully."

info "Test 3: Uploading small file (1KB)..."
SMALL_FILE="$TEST_DIR/small.bin"
dd if=/dev/urandom of="$SMALL_FILE" bs=1K count=1 status=none
SMALL_HASH=$(sha256sum "$SMALL_FILE" | awk '{print $1}')

OUTPUT=$(run_zd upload test-drive "$SMALL_FILE" --as-name small.bin 2>&1) || fail "Upload small file failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Uploaded test-drive/small.bin" || fail "Upload output mismatch."
pass "Small file uploaded."

info "Test 4: Uploading large file (10MB)..."
LARGE_FILE="$TEST_DIR/large.bin"
dd if=/dev/urandom of="$LARGE_FILE" bs=1M count=10 status=none
LARGE_HASH=$(sha256sum "$LARGE_FILE" | awk '{print $1}')

OUTPUT=$(run_zd upload test-drive "$LARGE_FILE" --as-name large.bin 2>&1) || fail "Upload large file failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Uploaded test-drive/large.bin" || fail "Large upload output mismatch."
pass "Large file uploaded (streaming encryption working)."

info "Test 5: Listing files in 'test-drive'..."
OUTPUT=$(run_zd list test-drive 2>&1) || fail "List files failed: $OUTPUT"
echo "$OUTPUT" | grep -q "small.bin" || fail "small.bin not found in list."
echo "$OUTPUT" | grep -q "large.bin" || fail "large.bin not found in list."
pass "Files listed correctly."

info "Test 6: Downloading small file..."
DL_SMALL="$TEST_DIR/dl_small.bin"
OUTPUT=$(run_zd download test-drive small.bin -o "$DL_SMALL" 2>&1) || fail "Download small file failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Downloaded test-drive/small.bin" || fail "Download output mismatch."

DL_SMALL_HASH=$(sha256sum "$DL_SMALL" | awk '{print $1}')
if [ "$SMALL_HASH" != "$DL_SMALL_HASH" ]; then
    fail "Small file checksum mismatch! ($SMALL_HASH != $DL_SMALL_HASH)"
fi
pass "Small file downloaded and integrity verified."

info "Test 7: Downloading large file..."
DL_LARGE="$TEST_DIR/dl_large.bin"
OUTPUT=$(run_zd download test-drive large.bin -o "$DL_LARGE" 2>&1) || fail "Download large file failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Downloaded test-drive/large.bin" || fail "Large download output mismatch."

DL_LARGE_HASH=$(sha256sum "$DL_LARGE" | awk '{print $1}')
if [ "$LARGE_HASH" != "$DL_LARGE_HASH" ]; then
    fail "Large file checksum mismatch! ($LARGE_HASH != $DL_LARGE_HASH)"
fi
pass "Large file downloaded and integrity verified."

info "Test 8: Daemon restart & state persistence..."
OUTPUT=$(run_zd stop 2>&1) || fail "Stop command failed: $OUTPUT"
sleep 2

info "Listing files again (daemon should auto-restart and fetch manifest from Nostr)..."
OUTPUT=$(run_zd list test-drive 2>&1) || fail "List after restart failed: $OUTPUT"
echo "$OUTPUT" | grep -q "small.bin" || fail "State lost after daemon restart! small.bin missing."
pass "Daemon restarted automatically and state persisted via Nostr."

info "Test 9: Deleting 'small.bin' with --purge..."
OUTPUT=$(run_zd delete test-drive small.bin --purge 2>&1) || fail "Delete file failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Deleted test-drive/small.bin" || fail "Delete output mismatch."

OUTPUT=$(run_zd list test-drive 2>&1)
echo "$OUTPUT" | grep -q "small.bin" && fail "small.bin still listed after delete." || true
pass "File deleted successfully."

info "Test 10: Deleting 'test-drive'..."
OUTPUT=$(run_zd delete test-drive 2>&1) || fail "Delete drive failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Deleted drive 'test-drive'" || fail "Delete drive output mismatch."

OUTPUT=$(run_zd list 2>&1)
echo "$OUTPUT" | grep -q "test-drive" && fail "test-drive still listed after delete." || true
pass "Drive deleted successfully."

echo ""
echo -e "\033[1;32m========================================\033[0m"
echo -e "\033[1;32mAll integration tests passed successfully!\033[0m"
echo -e "\033[1;32m========================================\033[0m"
