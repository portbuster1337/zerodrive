#!/bin/bash

set -e

ZERODRIVE_BIN="$(pwd)/target/debug/zerodrive"
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
TEST_DIR=$(mktemp -d -t zerodrive-test-XXXXXX)
FAKE_HOME="$TEST_DIR/home"
SOCKET_PATH="$FAKE_HOME/.local/share/zerodrive/daemon.sock"

mkdir -p "$FAKE_HOME"
export HOME="$FAKE_HOME"

GREEN='\033[1;32m'
RED='\033[1;31m'
BLUE='\033[1;34m'
NC='\033[0m'

WEB_PID=""

pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }

fail() {
    echo -e "${RED}✗ FAIL:${NC} $1"
    cleanup
    exit 1
}

info() { echo -e "${BLUE}• INFO:${NC} $1"; }

run_zd() {
    echo "$MNEMONIC" | "$ZERODRIVE_BIN" "$@"
}

retry() {
    local retries=$1
    local wait=$2
    shift 2
    local output
    for i in $(seq 1 $retries); do
        if output=$("$@" 2>&1); then
            echo "$output"
            return 0
        fi
        sleep $wait
    done
    echo "$output"
    return 1
}

cleanup() {
    info "Cleaning up test environment..."

    if [ -n "$WEB_PID" ]; then
        kill "$WEB_PID" >/dev/null 2>&1 || true
    fi

    echo "$MNEMONIC" | "$ZERODRIVE_BIN" stop >/dev/null 2>&1 || true

    for i in {1..10}; do
        if [ ! -e "$SOCKET_PATH" ]; then
            break
        fi
        sleep 0.5
    done

    rm -rf "$TEST_DIR"
}

trap cleanup EXIT INT TERM

if [ ! -f "$ZERODRIVE_BIN" ]; then
    fail "Binary not found at $ZERODRIVE_BIN. Please run 'cargo build' first."
fi

if ! command -v curl &> /dev/null; then
    fail "curl is required for integration tests but not installed."
fi

if ! command -v jq &> /dev/null; then
    fail "jq is required for integration tests but not installed."
fi

info "Starting integration tests in isolated environment: $TEST_DIR"

# ==========================================
# CLI TESTS
# ==========================================

info "Test 1: Checking daemon status (should auto-spawn)..."
OUTPUT=$(run_zd status 2>&1) || fail "Status command failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Daemon running" || fail "Daemon did not report running status."
pass "Daemon auto-spawned and is running."

info "Test 2: Dumping Nostr ID..."
OUTPUT=$(run_zd dump-id 2>&1) || fail "Dump-id failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Nostr public key:" || fail "Failed to print Nostr public key."
pass "Dump-id works and key derivation successful."

DRIVE_NAME="zd-test-$(date +%s)"

info "Test 3: Creating drive '${DRIVE_NAME}'..."
OUTPUT=$(retry 5 2 run_zd create-drive "$DRIVE_NAME") || fail "Create drive failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Drive '${DRIVE_NAME}' created" || fail "Drive creation output mismatch."
pass "Drive '${DRIVE_NAME}' created successfully."

info "Test 4: Listing all drives..."
OUTPUT=$(run_zd list 2>&1) || fail "List drives failed: $OUTPUT"
echo "$OUTPUT" | grep -q "$DRIVE_NAME" || fail "${DRIVE_NAME} not found in list of drives."
pass "Drive listed correctly."

info "Test 5: Uploading small and large files..."
SMALL_FILE="$TEST_DIR/small.bin"
LARGE_FILE="$TEST_DIR/large.bin"
dd if=/dev/urandom of="$SMALL_FILE" bs=1K count=1 status=none
dd if=/dev/urandom of="$LARGE_FILE" bs=1M count=5 status=none
SMALL_HASH=$(sha256sum "$SMALL_FILE" | awk '{print $1}')

OUTPUT=$(run_zd upload "$DRIVE_NAME" "$SMALL_FILE" "$LARGE_FILE" 2>&1) || fail "Upload multiple files failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Uploaded 2 file(s)" || fail "Did not upload 2 files."
pass "Multiple files uploaded successfully."

info "Test 6: Attempting to upload duplicate file (should fail)..."
OUTPUT=$(run_zd upload "$DRIVE_NAME" "$SMALL_FILE" 2>&1) || true
echo "$OUTPUT" | grep -q "already exists" || fail "Duplicate upload did not fail as expected."
pass "Duplicate upload prevented."

info "Test 7: Downloading specific file and verifying integrity..."
DL_SMALL="$TEST_DIR/dl_small.bin"
OUTPUT=$(run_zd download "$DRIVE_NAME" small.bin -o "$DL_SMALL" 2>&1) || fail "Download small file failed: $OUTPUT"
DL_SMALL_HASH=$(sha256sum "$DL_SMALL" | awk '{print $1}')
if [ "$SMALL_HASH" != "$DL_SMALL_HASH" ]; then
    fail "Small file checksum mismatch! ($SMALL_HASH != $DL_SMALL_HASH)"
fi
pass "Specific file downloaded and integrity verified."

info "Test 8: Downloading all files (*)..."
DL_DIR="$TEST_DIR/downloads"
mkdir -p "$DL_DIR"
cd "$DL_DIR"
OUTPUT=$(run_zd download "$DRIVE_NAME" "*" 2>&1) || fail "Download all failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Downloaded 2 file(s)" || fail "Did not download 2 files."
[ -f "small.bin" ] || fail "small.bin not found in download all"
[ -f "large.bin" ] || fail "large.bin not found in download all"
cd - >/dev/null
pass "Download all files works."

info "Test 9: Deleting 'small.bin' from manifest..."
OUTPUT=$(run_zd delete "$DRIVE_NAME" small.bin 2>&1) || fail "Delete failed: $OUTPUT"
OUTPUT=$(run_zd list "$DRIVE_NAME" 2>&1)
if echo "$OUTPUT" | grep -q "small.bin"; then
    fail "small.bin still listed after delete."
fi
pass "File deleted from manifest."

info "Test 10: Daemon restart & state persistence..."
OUTPUT=$(run_zd stop 2>&1) || fail "Stop command failed: $OUTPUT"

for i in {1..10}; do
    if [ ! -e "$SOCKET_PATH" ]; then break; fi
    sleep 0.5
done

info "Listing files again (daemon should auto-restart and fetch manifest from Nostr)..."
OUTPUT=$(retry 10 2 run_zd list "$DRIVE_NAME") || fail "List after restart failed: $OUTPUT"

if ! echo "$OUTPUT" | grep -q "large.bin"; then
    fail "State lost after daemon restart! large.bin missing. (Nostr propagation delay?)"
fi
pass "Daemon restarted automatically and state persisted via Nostr."

# ==========================================
# WEB API TESTS
# ==========================================

echo ""
info "Starting Web API Tests..."

info "Test 11: Starting Web UI in background..."
"$ZERODRIVE_BIN" --web > "$TEST_DIR/web.log" 2>&1 &
WEB_PID=$!

WEB_PORT=""
for i in {1..10}; do
    WEB_PORT=$(grep "Web UI:" "$TEST_DIR/web.log" | grep -o '[0-9]*' | head -n1)
    if [ -n "$WEB_PORT" ]; then break; fi
    sleep 0.5
done

if [ -z "$WEB_PORT" ]; then
    cat "$TEST_DIR/web.log"
    fail "Web UI did not start or port not found."
fi
BASE_URL="http://localhost:${WEB_PORT}"
pass "Web UI started on port $WEB_PORT."

info "Test 12: Web API - Unauthenticated access should fail (401)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/status")
if [ "$HTTP_CODE" != "401" ]; then fail "Expected 401, got $HTTP_CODE"; fi
pass "Unauthenticated access blocked."

info "Test 13: Web API - Setup and get session token..."
SETUP_RESP=$(curl -s -X POST "$BASE_URL/api/setup" -H "Content-Type: application/json" -d "{\"mnemonic\":\"$MNEMONIC\"}")
TOKEN=$(echo "$SETUP_RESP" | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    fail "Failed to get token: $SETUP_RESP"
fi
pass "Session token obtained successfully."

info "Test 14: Web API - Authenticated status check..."
STATUS_RESP=$(curl -s -w "\n%{http_code}" "$BASE_URL/api/status" -H "Authorization: Bearer $TOKEN")
HTTP_CODE=$(echo "$STATUS_RESP" | tail -n1)
BODY=$(echo "$STATUS_RESP" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then fail "Expected 200, got $HTTP_CODE: $BODY"; fi
echo "$BODY" | jq -e '.relays' > /dev/null || fail "Status response missing relays"
pass "Authenticated status check successful."

WEB_DRIVE="web-test-$(date +%s)"
info "Test 15: Web API - Create drive '$WEB_DRIVE'..."
CREATE_RESP=$(curl -s -X POST "$BASE_URL/api/drives" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$WEB_DRIVE\"}")

echo "$CREATE_RESP" | jq -e '.ok' > /dev/null || fail "Failed to create drive via web"
pass "Drive created via Web API."

info "Test 16: Web API - Upload file via Multipart..."
UPLOAD_RESP=$(curl -s -X POST "$BASE_URL/api/drives/$WEB_DRIVE/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@$SMALL_FILE;filename=web_small.bin")

echo "$UPLOAD_RESP" | jq -e '.ok' > /dev/null || fail "Upload failed: $UPLOAD_RESP"
echo "$UPLOAD_RESP" | jq -r '.name' | grep -q "web_small.bin" || fail "Upload returned wrong filename"
echo "$UPLOAD_RESP" | jq -e '.size' > /dev/null || fail "Upload response missing size"
pass "File uploaded via Web API."

info "Test 17: Web API - List files..."
LIST_RESP=$(curl -s "$BASE_URL/api/drives/$WEB_DRIVE/files" -H "Authorization: Bearer $TOKEN")
echo "$LIST_RESP" | jq -e '.[0].name' > /dev/null || fail "List failed or empty: $LIST_RESP"
echo "$LIST_RESP" | jq -r '.[0].name' | grep -q "web_small.bin" || fail "Uploaded file not in list"
echo "$LIST_RESP" | jq -e '.[0].shards' > /dev/null || fail "List response missing shards array"
pass "Files listed via Web API."

info "Test 18: Web API - Download file and verify integrity..."
DL_WEB="$TEST_DIR/dl_web.bin"
HTTP_CODE=$(curl -s -o "$DL_WEB" -w "%{http_code}" "$BASE_URL/api/drives/$WEB_DRIVE/download/web_small.bin" -H "Authorization: Bearer $TOKEN")

if [ "$HTTP_CODE" != "200" ]; then fail "Download failed with code $HTTP_CODE"; fi
DL_WEB_HASH=$(sha256sum "$DL_WEB" | awk '{print $1}')

if [ "$SMALL_HASH" != "$DL_WEB_HASH" ]; then
    fail "Web download checksum mismatch! ($SMALL_HASH != $DL_WEB_HASH)"
fi
pass "File downloaded via Web API and integrity verified."

info "Test 19: Web API - Delete file..."
DEL_RESP=$(curl -s -X DELETE "$BASE_URL/api/drives/$WEB_DRIVE/files/web_small.bin" -H "Authorization: Bearer $TOKEN")
echo "$DEL_RESP" | jq -e '.ok' > /dev/null || fail "Failed to delete file via web"

LIST_RESP=$(curl -s "$BASE_URL/api/drives/$WEB_DRIVE/files" -H "Authorization: Bearer $TOKEN")
if [ "$(echo "$LIST_RESP" | jq 'length')" -ne "0" ]; then
    fail "File still listed after web deletion"
fi
pass "File deleted via Web API."

# ==========================================
# STRESS & LIMIT TESTS
# ==========================================

echo ""
info "Starting Stress & Limit Tests..."

info "Test 20: Stopping Web UI and final CLI cleanup..."
kill "$WEB_PID" >/dev/null 2>&1 || true
WEB_PID=""
sleep 1

info "Deleting CLI drive '${DRIVE_NAME}' completely..."
OUTPUT=$(run_zd delete "$DRIVE_NAME" 2>&1) || fail "Delete drive failed: $OUTPUT"
OUTPUT=$(run_zd list 2>&1)
if echo "$OUTPUT" | grep -q "$DRIVE_NAME"; then
    fail "$DRIVE_NAME still listed after delete."
fi
pass "CLI Drive deleted successfully."

info "Test 21: Uploading 50 small files to test Nostr manifest splitting..."
MANIFEST_DRIVE="manifest-test-$(date +%s)"
OUTPUT=$(retry 5 2 run_zd create-drive "$MANIFEST_DRIVE") || fail "Create manifest test drive failed: $OUTPUT"

for i in $(seq 1 200); do
    echo "file $i" > "$TEST_DIR/small_$i.txt"
done

OUTPUT=$(run_zd upload "$MANIFEST_DRIVE" "$TEST_DIR"/small_*.txt 2>&1) || fail "Upload 200 small files failed: $OUTPUT"
echo "$OUTPUT" | grep -q "Uploaded 200 file(s)" || fail "Did not upload 200 files."
pass "200 small files uploaded."

info "Test 22: Listing and downloading from split manifest..."
OUTPUT=$(run_zd list "$MANIFEST_DRIVE" 2>&1) || fail "List split manifest drive failed: $OUTPUT"
FILE_COUNT=$(echo "$OUTPUT" | grep -c "small_")
if [ "$FILE_COUNT" -ne "200" ]; then
    fail "Expected 200 files in list, got $FILE_COUNT"
fi

OUTPUT=$(run_zd download "$MANIFEST_DRIVE" small_100.txt -o "$TEST_DIR/dl_small_100.txt" 2>&1) || fail "Download from split manifest failed: $OUTPUT"
if [ "$(cat "$TEST_DIR/dl_small_100.txt")" != "file 100" ]; then
    fail "Downloaded file content mismatch from split manifest"
fi
pass "Split manifest list/download verified."

# Cleanup manifest test drive
run_zd delete "$MANIFEST_DRIVE" >/dev/null 2>&1 || true

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All integration tests passed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
