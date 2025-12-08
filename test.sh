#!/bin/bash

# ===================== Configuration =====================
RUNNER="${RUNNER:-cargo}"
BASE_FLAGS="${BASE_FLAGS:---all-targets}"
INSTALL_FLAGS="${INSTALL_FLAGS:---locked}"
LOG_DIR="${LOG_DIR:-target/test-logs}"

# OPTIMIZATION: Run tests in parallel
PARALLEL_JOBS="${PARALLEL_JOBS:-$(nproc)}"

# Matrix of combinations per package
read -r -d '' MATRIX <<'EOF'
ave-identity|--all-features
ave-tell|--all-features
ave-network|--all-features
ave-core|--no-default-features --features sqlite,ext-sqlite;--no-default-features --features rocksdb,ext-sqlite
ave-bridge|--no-default-features --features sqlite,ext-sqlite;--no-default-features --features rocksdb,ext-sqlite
ave-http|--no-default-features --features sqlite,ext-sqlite;--no-default-features --features rocksdb,ext-sqlite
EOF

# Global state
SUCCESSES=()
FAIL_LABELS=()
FAIL_DETAILS=()
FAIL_LOGS=()
EXIT_CODE=0
START_TIME=$(date +%s)
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Colors
if [ -n "${NO_COLOR:-}" ]; then
  BOLD=""; DIM=""; RED=""; GREEN=""; CYAN=""; YELLOW=""; RESET=""
  BLUE=""; MAGENTA=""
else
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  RED=$'\033[31m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  BLUE=$'\033[34m'
  MAGENTA=$'\033[35m'
  CYAN=$'\033[36m'
  RESET=$'\033[0m'
fi

# ======== Simplified UI functions ========

print_header() {
  echo
  echo "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo "${BOLD}${CYAN}  $1${RESET}"
  echo "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo
}

banner() {
  local title="$1"
  local subtitle="$2"
  echo
  echo "${CYAN}▶${RESET} ${BOLD}${MAGENTA}${title}${RESET}"
  if [ -n "$subtitle" ]; then
    echo "  ${DIM}${subtitle}${RESET}"
  fi
}

print_result() {
  local status="$1"
  local logfile="$2"

  if [ "$status" = "OK" ]; then
    echo "  ${GREEN}✔ PASSED${RESET} ${DIM}(log: ${logfile})${RESET}"
  else
    echo "  ${RED}✖ FAILED${RESET} ${YELLOW}(exit: $status)${RESET} ${DIM}(log: ${logfile})${RESET}"
  fi
}

# ======== Utilities ========

ensure_tools() {
  print_header "CHECKING TOOLS"

  if ! command -v cargo >/dev/null 2>&1; then
    echo "${RED}✖ Error: cargo not found${RESET}" >&2
    exit 1
  fi
  echo "${GREEN}✔${RESET} cargo: $(cargo --version)"

  if ! cargo hack --version >/dev/null 2>&1; then
    echo "${YELLOW}⚠ Installing cargo-hack...${RESET}"
    cargo install cargo-hack ${INSTALL_FLAGS}
    export PATH="$HOME/.cargo/bin:$PATH"
  fi
  echo "${GREEN}✔${RESET} cargo-hack: $(cargo hack --version)"

  # Disable sccache for better performance
  unset RUSTC_WRAPPER
  echo "${BLUE}ℹ${RESET} sccache: DISABLED (better performance without cache)"

  mkdir -p "${LOG_DIR}"
  echo "${GREEN}✔${RESET} Log directory: ${LOG_DIR}"
  echo "${BLUE}⚡${RESET} Parallel jobs: ${PARALLEL_JOBS}"
}

normalize_combo() {
  echo "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/[[:space:]]\{1,\}/ /g'
}

extract_failures() {
  # Extract test names from "failures:" section
  awk '
    /^failures:[[:space:]]*$/ { in=1; next }
    in && /^[[:space:]]*$/ { in=0 }
    in {
      sub(/^[[:space:]]+/, "", $0)
      if ($0 != "") print $0
    }
  ' "$1" 2>/dev/null

  # Also try to extract from "---- test_name stdout ----" format
  grep -oP '^---- \K[^ ]+(?= (stdout|stderr) ----)' "$1" 2>/dev/null | sort -u
}

extract_test_stats() {
  local total_passed=0
  local total_failed=0

  # Sum ALL "test result:" lines (unittests, integration tests, doctests)
  while IFS= read -r line; do
    local passed failed
    passed=$(echo "$line" | grep -oP '\d+(?= passed)' || echo "0")
    failed=$(echo "$line" | grep -oP '\d+(?= failed)' || echo "0")
    total_passed=$((total_passed + passed))
    total_failed=$((total_failed + failed))
  done < <(grep -E 'test result:' "$1" 2>/dev/null)

  echo "passed:$total_passed failed:$total_failed"
}

run_step() {
  local label="$1"; shift
  local subtitle="$1"; shift

  banner "$label" "$subtitle"

  local safe
  safe="$(echo "${label} ${subtitle}" | tr ' /[]:,|' '________')"
  local logfile="${LOG_DIR}/$(date +%Y%m%d_%H%M%S)_${safe}.log"

  if "$@" > >(tee "${logfile}") 2>&1; then
    print_result "OK" "${logfile}"
    SUCCESSES+=("${label} | ${subtitle}")

    local stats
    stats=$(extract_test_stats "${logfile}")
    local passed failed
    passed=$(echo "$stats" | cut -d: -f2 | cut -d' ' -f1)
    failed=$(echo "$stats" | cut -d: -f3)
    PASSED_TESTS=$((PASSED_TESTS + passed))
    TOTAL_TESTS=$((TOTAL_TESTS + passed + failed))
  else
    local rc=$?
    print_result "$rc" "${logfile}"

    local summary
    summary="$(grep -E 'test result:' "${logfile}" | tail -1 || echo "")"

    local failed_list
    failed_list="$(extract_failures "${logfile}")"

    local details=""
    if [ -n "${summary}" ]; then
      details+="${summary}"$'\n'
    fi
    if [ -n "${failed_list}" ]; then
      details+="Failed tests:"$'\n'"${failed_list}"
    fi
    if [ -z "${details}" ]; then
      details="(See log for details)"
    fi

    FAIL_LABELS+=("${label} | ${subtitle}")
    FAIL_DETAILS+=("${details}")
    FAIL_LOGS+=("${logfile}")
    EXIT_CODE=1

    local stats
    stats=$(extract_test_stats "${logfile}")
    local passed failed
    passed=$(echo "$stats" | cut -d: -f2 | cut -d' ' -f1)
    failed=$(echo "$stats" | cut -d: -f3)
    PASSED_TESTS=$((PASSED_TESTS + passed))
    FAILED_TESTS=$((FAILED_TESTS + failed))
    TOTAL_TESTS=$((TOTAL_TESTS + passed + failed))
  fi
  echo
}

filter_matrix_lines() {
  if [[ "$#" -eq 0 ]]; then
    echo "${MATRIX}"
    return
  fi
  local filtered=""
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    local pkg="${line%%|*}"
    local want
    for want in "$@"; do
      if [[ "${pkg}" == "${want}" ]]; then
        filtered+="${line}"$'\n'
        break
      fi
    done
  done <<< "${MATRIX}"
  echo "${filtered}"
}

GROUP_KEYS=()
GROUP_PKGS=()

add_to_group() {
  local key="$1"
  local pkg="$2"
  local i
  for ((i=0; i<${#GROUP_KEYS[@]}; i++)); do
    if [[ "${GROUP_KEYS[$i]}" == "${key}" ]]; then
      case " ${GROUP_PKGS[$i]} " in
        *" ${pkg} "*) : ;;
        *) GROUP_PKGS[$i]="${GROUP_PKGS[$i]} ${pkg}" ;;
      esac
      return
    fi
  done
  GROUP_KEYS+=("${key}")
  GROUP_PKGS+=("${pkg}")
}

build_groups() {
  local lines
  lines="$(filter_matrix_lines "$@")"
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    local pkg combos_str
    pkg="${line%%|*}"
    combos_str="${line#*|}"

    IFS=';' read -r -a combos <<< "${combos_str}"
    local combo
    for combo in "${combos[@]}"; do
      combo="$(echo "${combo}" | xargs)"
      [[ -z "${combo}" ]] && continue
      local key
      key="$(normalize_combo "${combo}")"
      add_to_group "${key}" "${pkg}"
    done
  done <<< "${lines}"
}

run_groups() {
  local total_groups=${#GROUP_KEYS[@]}
  local current_group=0

  print_header "RUNNING TESTS"

  for ((i=0; i<${#GROUP_KEYS[@]}; i++)); do
    local key="${GROUP_KEYS[$i]}"
    local pkgs="${GROUP_PKGS[$i]}"
    current_group=$((current_group + 1))

    # ===== Pre-compilation with parallel optimization =====
    local pre_label="🔧 PRE-COMPILATION [${current_group}/${total_groups}]"
    local pre_sub="Packages: $(echo "${pkgs}" | tr ' ' ', ') | Flags: ${key} ${BASE_FLAGS}"
    local pre_cmd=()

    pre_cmd=(cargo hack test)
    local p
    for p in ${pkgs}; do pre_cmd+=(-p "$p"); done
    # shellcheck disable=SC2206
    local key_arr=( $key )
    # shellcheck disable=SC2206
    local base_arr=( $BASE_FLAGS )
    pre_cmd+=("${key_arr[@]}")
    if [[ -n "${BASE_FLAGS}" ]]; then pre_cmd+=("${base_arr[@]}"); fi

    # OPTIMIZATION: Add parallelization flags
    pre_cmd+=(-j "${PARALLEL_JOBS}")
    pre_cmd+=(--no-run)

    run_step "${pre_label}" "${pre_sub}" "${pre_cmd[@]}"

    # ===== Individual execution per package =====
    local pkg_count=0
    local total_pkgs=$(echo "${pkgs}" | wc -w)

    for p in ${pkgs}; do
      pkg_count=$((pkg_count + 1))
      local label="📦 ${p} [${pkg_count}/${total_pkgs}]"
      local subtitle="Flags: ${key} ${BASE_FLAGS}"
      local cmd=()

      if [[ "${RUNNER}" == "cargo" ]]; then
        cmd=(cargo test -p "${p}")
      else
        # shellcheck disable=SC2206
        cmd=( ${RUNNER} -p "${p}" )
      fi

      cmd+=("${key_arr[@]}")
      if [[ -n "${BASE_FLAGS}" ]]; then cmd+=("${base_arr[@]}"); fi

      # OPTIMIZATION: Tests in parallel
      cmd+=(-j "${PARALLEL_JOBS}")

      run_step "${label}" "${subtitle}" "${cmd[@]}"
    done
  done
}

format_duration() {
  local duration=$1
  local hours=$((duration / 3600))
  local minutes=$(((duration % 3600) / 60))
  local seconds=$((duration % 60))

  if [ $hours -gt 0 ]; then
    printf "%dh %dm %ds" $hours $minutes $seconds
  elif [ $minutes -gt 0 ]; then
    printf "%dm %ds" $minutes $seconds
  else
    printf "%ds" $seconds
  fi
}

print_summary() {
  local end_time=$(date +%s)
  local duration=$((end_time - START_TIME))

  echo
  print_header "FINAL SUMMARY"

  # Statistics
  echo "${BOLD}Statistics:${RESET}"
  echo "  ${GREEN}✔${RESET} Successful tests:  ${#SUCCESSES[@]}"
  echo "  ${RED}✖${RESET} Failed tests:      ${#FAIL_LABELS[@]}"
  echo "  ${BLUE}⧗${RESET} Total duration:    $(format_duration $duration)"
  echo "  ${MAGENTA}Σ${RESET} Tests executed:    $TOTAL_TESTS"

  if [ $TOTAL_TESTS -gt 0 ]; then
    local success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    echo "  ${YELLOW}%${RESET} Success rate:      ${success_rate}%"
  fi
  echo

  # Successful tests
  if [ "${#SUCCESSES[@]}" -gt 0 ]; then
    echo "${BOLD}${GREEN}✔ SUCCESSFUL TESTS (${#SUCCESSES[@]}):${RESET}"
    local s
    for s in "${SUCCESSES[@]}"; do
      echo "  ${DIM}•${RESET} $s"
    done
    echo
  fi

  # Failed tests
  if [ "${#FAIL_LABELS[@]}" -gt 0 ]; then
    echo "${BOLD}${RED}✖ FAILED TESTS (${#FAIL_LABELS[@]}):${RESET}"
    for ((i=0; i<${#FAIL_LABELS[@]}; i++)); do
      echo
      local label="${FAIL_LABELS[$i]}"
      local package=$(echo "$label" | sed -n 's/.*📦 \([^ ]*\).*/\1/p')
      local features=$(echo "$label" | grep -oP 'Flags: \K.*' || echo "default")

      if [ -n "$package" ]; then
        echo "  ${RED}⚠${RESET} ${BOLD}Package:${RESET} ${CYAN}${package}${RESET}"
        echo "     ${BOLD}Features:${RESET} ${YELLOW}${features}${RESET}"
      else
        echo "  ${RED}⚠${RESET} ${BOLD}${label}${RESET}"
      fi
      echo "     ${DIM}Log: ${FAIL_LOGS[$i]}${RESET}"
      echo

      # Show failed test names
      local failed_list
      failed_list="$(extract_failures "${FAIL_LOGS[$i]}")"
      if [ -n "${failed_list}" ]; then
        echo "     ${BOLD}Failed tests:${RESET}"
        echo "${failed_list}" | while IFS= read -r test_name; do
          [ -n "$test_name" ] && echo "       ${RED}✖${RESET} ${test_name}"
        done
      fi
      echo

      # Show summary line if present
      local summary
      summary="$(grep -E 'test result:' "${FAIL_LOGS[$i]}" | tail -1 || echo "")"
      if [ -n "${summary}" ]; then
        echo "     ${DIM}${summary}${RESET}"
      fi
    done
    echo
  fi

  echo "${DIM}Logs saved in: ${LOG_DIR}${RESET}"
  echo

  # Final result
  if [ "${EXIT_CODE}" -eq 0 ]; then
    echo "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo "${GREEN}${BOLD}  ✔ ALL TESTS PASSED${RESET}"
    echo "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  else
    echo "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo "${RED}${BOLD}  ✖ SOME TESTS FAILED${RESET}"
    echo "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  fi
  echo
}

main() {
  print_header "AVE TEST SUITE"
  ensure_tools
  build_groups "$@"
  run_groups
  print_summary
  exit "${EXIT_CODE}"
}

main "$@"
