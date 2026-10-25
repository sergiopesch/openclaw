#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUN_SCRIPT="${1:-$SCRIPT_DIR/run.sh}"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/bin" "$TEST_DIR/home"

# Exercise the full smoke script without npm, network access, or installation.
cat > "$TEST_DIR/bin/npm" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" != 'view openclaw version' ]]; then
  echo "Unexpected npm operation: $*" >&2
  exit 1
fi
printf '%s\n' "$SMOKE_EXPECTED_NPM_VERSION"
SH
cat > "$TEST_DIR/bin/curl" <<'SH'
#!/usr/bin/env bash
printf '#!/usr/bin/env bash\n:\n'
SH
cat > "$TEST_DIR/bin/openclaw" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  --version) printf '%s\n' "$SMOKE_TEST_VERSION" ;;
  --help) exit 0 ;;
  *) exit 1 ;;
esac
SH
chmod +x "$TEST_DIR/bin/"*

check_version() {
  local expected_result="$1" output="$2" latest="${3:-2026.10.7}"
  local result=0
  env -i PATH="$TEST_DIR/bin:/usr/bin:/bin" HOME="$TEST_DIR/home" \
    OPENCLAW_INSTALL_URL=https://example.invalid/install.sh \
    OPENCLAW_INSTALL_SMOKE_SKIP_PREVIOUS=1 \
    OPENCLAW_INSTALL_SMOKE_PREVIOUS=2026.10.6 \
    SMOKE_EXPECTED_NPM_VERSION="$latest" SMOKE_TEST_VERSION="$output" \
    bash "$RUN_SCRIPT" > "$TEST_DIR/result.log" 2>&1 || result=$?
  if [[ "$expected_result" == pass && "$result" != 0 ]] ||
    [[ "$expected_result" == fail && "$result" == 0 ]]; then
    cat "$TEST_DIR/result.log" >&2
    echo "Unexpected smoke result for: $output (exit $result)" >&2
    exit 1
  fi
}

check_version pass '2026.10.7'
check_version pass 'OpenClaw 2026.10.7 (157d8c2)'
check_version pass 'OpenClaw 2026.10.7'
check_version pass 'OpenClaw 2026.10.7-beta.1 (157d8c2)' '2026.10.7-beta.1'
check_version pass '1.2.3' '1.2.3'
check_version fail 'OpenClaw 2026.10.6 (157d8c2)'
check_version fail 'anything 2026.10.7'
check_version fail 'OpenClaw 2026.10.7 (not-a-git-sha)'
check_version fail '2026.10.7 unexpected suffix'
printf 'Installer version checks passed: 5 supported formats and 4 rejection controls.\n'
