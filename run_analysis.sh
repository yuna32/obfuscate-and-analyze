#!/usr/bin/env bash
# run_analysis.sh
# experiment/ 디렉토리 아래 바이너리 10개를 순서대로 자동 분석한다.
# 각 바이너리 경로에서 category(easy/hard)와 level을 파싱하여
# analyzer.py --auto-select 로 LLM 분석 후 results.csv에 누적한다.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="$SCRIPT_DIR/analyzer/analyzer.py"
EXPERIMENT_DIR="/mnt/c/users/gram/desktop/pj/experiment"
MAX=10

# ── 사전 검사 ──────────────────────────────────────────
if [ ! -f "$ANALYZER" ]; then
    echo "[오류] analyzer.py를 찾을 수 없습니다: $ANALYZER" >&2
    exit 1
fi

if [ ! -d "$EXPERIMENT_DIR" ]; then
    echo "[오류] experiment/ 디렉토리가 없습니다: $EXPERIMENT_DIR" >&2
    exit 1
fi

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "[오류] ANTHROPIC_API_KEY 환경변수가 설정되지 않았습니다." >&2
    exit 1
fi

# ── 레벨 파싱 함수 ─────────────────────────────────────
# 파일명에서 난독화 레벨을 추출한다.
# 우선순위: L1L2L3L4 > L1L2L3 > L1L2 > L1 > none
parse_level() {
    local filename="$1"
    if [[ "$filename" == *"L1L2L3L4"* ]]; then echo "L1L2L3L4"
    elif [[ "$filename" == *"L1L2L3"* ]];  then echo "L1L2L3"
    elif [[ "$filename" == *"L1L2"* ]];    then echo "L1L2"
    elif [[ "$filename" == *"_L1"* || "$filename" == *"-L1"* || "$filename" == *"L1" ]]; then echo "L1"
    elif [[ "$filename" == *"none"* ]];    then echo "none"
    else echo "unknown"
    fi
}

# ── 메인 루프 ─────────────────────────────────────────
COUNT=0

# ELF 바이너리만 수집 (실행 가능한 파일, .sh/.py/.csv 제외)
while IFS= read -r -d '' binary; do
    [ "$COUNT" -ge "$MAX" ] && break

    # 파일이 ELF인지 확인 (magic bytes: 7f 45 4c 46)
    magic=$(xxd -p -l 4 "$binary" 2>/dev/null || true)
    if [ "$magic" != "7f454c46" ]; then
        continue
    fi

    filename=$(basename "$binary")
    parent_dir=$(basename "$(dirname "$binary")")

    # category: 부모 디렉토리 이름이 easy/hard 이면 사용, 아니면 파일명에서 파싱
    if [[ "$parent_dir" == "easy" || "$parent_dir" == "hard" ]]; then
        category="$parent_dir"
    elif [[ "$filename" == *"easy"* ]]; then
        category="easy"
    elif [[ "$filename" == *"hard"* ]]; then
        category="hard"
    else
        category="unknown"
    fi

    level=$(parse_level "$filename")

    COUNT=$((COUNT + 1))
    echo "──────────────────────────────────────────────────"
    echo "[$COUNT/$MAX] 바이너리 : $binary"
    echo "      category : $category"
    echo "      level    : $level"
    echo "──────────────────────────────────────────────────"

    cd "$SCRIPT_DIR" && python -m analyzer.analyzer \
    --binary "$binary" \
    --category "$category" \
    --level "$level" \
    --auto-select

    echo ""
done < <(find "$EXPERIMENT_DIR" -type f ! -name "*.sh" ! -name "*.py" \
    ! -name "*.csv" ! -name "*.txt" ! -name "*.md" \
    ! -name "*_src" -print0 | sort -z)

echo "══════════════════════════════════════════════════"
echo "분석 완료: 총 ${COUNT}개 바이너리"
echo "results.csv 업데이트 완료"
echo "══════════════════════════════════════════════════"
