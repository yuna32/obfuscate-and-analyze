#!/usr/bin/env bash
# run_experiment.sh
# 2개 타깃 × 5개 레이어 조합 = 총 10개 바이너리를 생성하고
# 무결성 검증, stats 측정, 실패 기록을 자동화한다.

set -uo pipefail

# ── 경로 설정 ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBFUSCATOR="$SCRIPT_DIR/obfuscator/obfuscator.py"
VENV="$HOME/pj_venv"
EXPERIMENT="$SCRIPT_DIR/experiment"

PYTHON="$VENV/bin/python3"
VERIFY_ARG="World"
STATS_CSV="$EXPERIMENT/stats.csv"

# ── 레이어 정의 ───────────────────────────────────────────────────────────────
LEVEL_NAMES=("none" "L1" "L1L2" "L1L2L3" "L1L2L3L4")
LEVEL_ARGS=("" "L1" "L1,L2" "L1,L2,L3" "L1,L2,L3,L4")

# ── 헬퍼 함수 ────────────────────────────────────────────────────────────────
log()  { echo "[$(date +%H:%M:%S)] $*"; }
ok()   { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; }

smoke_test() {
    # 바이너리를 실제로 실행해 종료코드 0을 반환하는지 확인
    local bin="$1"
    local arg="$2"
    chmod +x "$bin" 2>/dev/null || true
    "$bin" "$arg" >/dev/null 2>&1
}

write_none_stats() {
    # "none" 레벨(원본 복사)에 대한 stats row를 Python으로 직접 기록
    local bin="$1"
    local target_name="$2"
    "$PYTHON" - "$bin" "$target_name" "$STATS_CSV" <<'PYEOF'
import sys, os, csv
from elftools.elf.elffile import ELFFile

bin_path, target_name, csv_path = sys.argv[1], sys.argv[2], sys.argv[3]

PF_X = 0x1
with open(bin_path, "rb") as f:
    elf = ELFFile(f)
    pt_load_filesz = max(
        (seg.header.p_filesz for seg in elf.iter_segments()
         if seg.header.p_type == "PT_LOAD" and (seg.header.p_flags & PF_X)),
        default=0
    )

file_size = os.path.getsize(bin_path)
header = ["target", "level", "file_size_bytes", "pt_load_filesz", "injected_count"]
needs_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0
with open(csv_path, "a", newline="") as f:
    w = csv.writer(f)
    if needs_header:
        w.writerow(header)
    w.writerow([target_name, "none", file_size, pt_load_filesz, 0])
PYEOF
}

# ── 사전 확인 ────────────────────────────────────────────────────────────────
for req in gcc; do
    if ! command -v "$req" &>/dev/null; then
        echo "ERROR: '$req' not found. 필요한 패키지를 설치하세요." >&2
        exit 1
    fi
done

if [ ! -f "$PYTHON" ]; then
    echo "ERROR: venv not found at $VENV" >&2
    echo "  python3 -m venv .venv && source .venv/bin/activate && pip install -r obfuscator/requirements.txt" >&2
    exit 1
fi

# ── 디렉토리 초기화 ──────────────────────────────────────────────────────────
mkdir -p "$EXPERIMENT/easy" "$EXPERIMENT/hard"
FAILED_LOG="$EXPERIMENT/failed.log"
> "$FAILED_LOG"
# stats.csv는 obfuscator/write_none_stats가 header를 관리하므로 초기화만
> "$STATS_CSV"

# ── 컴파일 ───────────────────────────────────────────────────────────────────
log "=== 소스 컴파일 ==="

declare -A SRC_BIN
for TARGET in easy hard; do
    SRC_BIN[$TARGET]="$EXPERIMENT/${TARGET}/target_${TARGET}_src"
    if gcc -o "${SRC_BIN[$TARGET]}" "$SCRIPT_DIR/target_${TARGET}.c" \
    -no-pie -fno-stack-protector -g -falign-functions=32 -falign-functions=32 2>&1; then
        ok "target_${TARGET} 컴파일 완료"
    else
        echo "ERROR: target_${TARGET}.c 컴파일 실패 — 중단" >&2
        exit 1
    fi
done

# ── 메인 루프 ────────────────────────────────────────────────────────────────
log "=== 난독화 시작 (${#LEVEL_NAMES[@]} 레이어 × 2 타깃) ==="

TOTAL=0
PASS=0
FAIL=0

for TARGET in easy hard; do
    echo ""
    log "── target_${TARGET} ──"
    SRC="${SRC_BIN[$TARGET]}"
    SUBDIR="$EXPERIMENT/$TARGET"

    for IDX in "${!LEVEL_NAMES[@]}"; do
        LEVEL="${LEVEL_NAMES[$IDX]}"
        ARG="${LEVEL_ARGS[$IDX]}"
        OUT="$SUBDIR/target_${TARGET}_${LEVEL}"
        TOTAL=$((TOTAL + 1))

        printf "  [%d/%d] %-12s → %s ... " \
               "$TOTAL" "$(( ${#LEVEL_NAMES[@]} * 2 ))" "$LEVEL" "$(basename "$OUT")"

        ERROR_MSG=""

        if [ "$LEVEL" = "none" ]; then
            # 원본 복사 후 smoke-test, stats는 Python 인라인으로 기록
            if cp "$SRC" "$OUT" && smoke_test "$OUT" "$VERIFY_ARG"; then
                write_none_stats "$OUT" "target_${TARGET}" || true
            else
                ERROR_MSG="smoke_test 실패"
            fi
        else
            # obfuscator 실행 (stdout/stderr 캡처, 실패 시 ERROR_MSG에 저장)
            OBF_LOG=$("$PYTHON" "$OBFUSCATOR" \
    -i "$SRC" -o "$OUT" \
    --levels "$ARG" \
    --verify --verify-args "$VERIFY_ARG" \
    --stats-out "$STATS_CSV" \
    --stats-target "target_${TARGET}" 2>&1) || ERROR_MSG="$OBF_LOG"
        fi

        if [ -z "$ERROR_MSG" ]; then
            echo "PASS"
            PASS=$((PASS + 1))
        else
            echo "FAIL"
            ENTRY="target_${TARGET} / ${LEVEL}: ${ERROR_MSG}"
            echo "$ENTRY" >> "$FAILED_LOG"
            fail "$ENTRY"
            FAIL=$((FAIL + 1))
        fi
    done
done

# ── 요약 ─────────────────────────────────────────────────────────────────────
echo ""
log "=== 결과 요약 ==="
echo "  총 바이너리  : $TOTAL"
echo "  성공         : $PASS"
echo "  실패         : $FAIL"
echo ""
echo "  출력 디렉토리: $EXPERIMENT/"
echo "  stats.csv    : $STATS_CSV"
[ "$FAIL" -gt 0 ] && echo "  failed.log   : $FAILED_LOG"

echo ""
log "=== stats.csv 미리보기 ==="
column -t -s ',' "$STATS_CSV"

exit $FAIL
