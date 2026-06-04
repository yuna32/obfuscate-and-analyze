# ELF Binary Reverse Engineering TUI — 사용 가이드

## 개요

난독화된 x86-64 ELF 바이너리를 터미널에서 분석하는 TUI 도구입니다.  
GDB/pwndbg처럼 터미널에서 동작하며, Claude LLM이 디스어셈블 결과를 실시간 스트리밍으로 설명합니다.

---

## 파일 구조

```
pj2/
├── requirements.txt
├── GUIDE.md                 ← 이 파일
├── run_analysis.sh          ← 실험 자동화 스크립트 (10개 바이너리 일괄 분석)
├── plot_results.py          ← 그래프 생성 스크립트
├── results.csv              ← 분석 결과 자동 누적 (실행 후 생성)
├── results_vuln_detection.png   ← 취약점 탐지율 그래프 (plot 후 생성)
├── results_cfg_complexity.png   ← CFG 복잡도 그래프 (plot 후 생성)
├── experiment/              ← 분석 대상 바이너리 디렉토리
│   ├── easy/
│   │   ├── target_easy_none
│   │   ├── target_easy_L1
│   │   └── ...
│   └── hard/
│       ├── target_hard_none
│       └── ...
└── analyzer/
    ├── analyzer.py          ← 메인 진입점 (TUI 루프 + 자동 선택 모드)
    ├── core/
    │   ├── elf_loader.py    # ELF 파싱, 함수 추출
    │   ├── disasm.py        # capstone 래퍼, 기본 블록 추출
    │   ├── cfg.py           # networkx CFG + 복잡도 계산
    │   └── llm.py           # Claude API 스트리밍 호출
    └── ui/
        ├── layout.py        # rich Layout 정의, 패널 관리
        └── keys.py          # readchar 키 입력 처리
```

---

## 설치

### 1. 의존성 설치

```bash
cd pj2
pip install -r requirements.txt
```

### 2. API 키 설정

Claude API 키를 환경변수로 주입합니다.

**Linux / macOS:**
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

**Windows (PowerShell):**
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

**Windows (CMD):**
```cmd
set ANTHROPIC_API_KEY=sk-ant-...
```

> `--no-llm` 플래그를 사용하면 API 키 없이도 동작합니다.

---

## 실행

### 기본 실행

```bash
python analyzer/analyzer.py --binary ./obf_binary
```

### LLM 없이 실행 (디스어셈블 + CFG 통계만)

```bash
python analyzer/analyzer.py --binary ./obf_binary --no-llm
```

---

## UI 레이아웃

```
┌──────────────────┬───────────────────────────────────┐
│  함수 목록        │  디스어셈블 뷰                     │
│  (선택 함수 반전) │  (어셈블리 신택스 하이라이팅)       │
├──────────────────┼───────────────────────────────────┤
│  CFG 통계        │  LLM 분석 결과                    │
│  (수치 테이블)   │  (스트리밍 JSON 파싱 결과)         │
└──────────────────┴───────────────────────────────────┘
  [q]uit  [a]nalyze  [↑↓ / j·k] 함수 이동  [r]efresh
```

---

## 키 조작

| 키 | 동작 |
|---|---|
| `q` | 프로그램 종료 |
| `a` | 현재 선택 함수를 Claude LLM으로 분석 |
| `↑` / `k` | 함수 목록 위로 이동 |
| `↓` / `j` | 함수 목록 아래로 이동 |
| `r` | 현재 함수 디스어셈블 새로고침 |

---

## 각 패널 설명

### 함수 목록 (좌상단)

- ELF 심볼 테이블(`.symtab`)이 있으면 실제 함수명과 주소를 표시
- **Stripped 바이너리**(심볼 없음)의 경우 `.text` 섹션에서 휴리스틱 탐지
  - `ENDBR64` (`F3 0F 1E FA`) 패턴 탐지
  - `PUSH RBP; MOV RBP,RSP` (`55 48 89 E5`) 패턴 탐지
  - 자동 명명: `sub_<주소>` 형태

### 디스어셈블 뷰 (우상단)

- capstone 엔진(x86-64)으로 디스어셈블
- 형식: `0x<주소>  <바이트>  <니모닉> <오퍼랜드>`
- rich Syntax로 어셈블리 컬러 하이라이팅 적용

### CFG 통계 (좌하단)

ASCII 그래프 렌더링 없이 수치만 표시:

| 항목 | 설명 |
|---|---|
| 기본 블록 수 | JMP/JCC/RET/CALL 기준으로 분할한 블록 수 |
| 엣지 수 | 블록 간 제어 흐름 엣지 수 |
| Cyclomatic Complexity | `E - N + 2` 공식 (코드 복잡도 지표) |
| 최장 경로 길이 | networkx DAG 최장 경로 (사이클 있으면 노드 수로 대체) |

> Cyclomatic Complexity가 높을수록 분기가 많고 테스트가 어려운 함수입니다.

### LLM 분석 결과 (우하단)

`[a]` 키 입력 시 스트리밍으로 출력되며, 분석 완료 후 아래 항목을 표시:

- **요약**: 함수 기능 한국어 설명 (2~3문장)
- **취약점**: Buffer Overflow, Format String 등 발견 여부 및 설명
- **난독화 기법**: Junk Instruction, Opaque Predicate, CFF, String Encryption 등

---

## 결과 자동 저장 (`results.csv`)

`[a]` 키로 LLM 분석할 때마다, 또는 `--auto-select` 자동화 모드에서  
프로젝트 루트의 `results.csv`에 자동 append됩니다.

기존 CSV에 새 컬럼이 없는 경우 **자동 마이그레이션**됩니다 (기존 행에는 `unknown` 채움).

### CSV 컬럼

| 컬럼 | 설명 |
|---|---|
| `binary` | 분석한 바이너리 파일명 |
| `function` | 함수명 |
| `blocks` | 기본 블록 수 |
| `edges` | CFG 엣지 수 |
| `cyclomatic_complexity` | Cyclomatic Complexity |
| `llm_vuln_found` | LLM이 취약점 발견 여부 (`true`/`false`) |
| `llm_obfuscation_detected` | LLM이 난독화 탐지 여부 |
| `llm_techniques` | 탐지된 난독화 기법 (세미콜론 구분) |
| `vuln_category` | 취약점 난이도 (`easy` / `hard` / `unknown`) |
| `binary_level` | 난독화 레벨 (`none` / `L1` / `L1L2` / `L1L2L3` / `L1L2L3L4` / `unknown`) |
| `timestamp` | 분석 시각 (`YYYY-MM-DD HH:MM:SS`) |

---

## 동작 원리

```
ELF 바이너리
    │
    ▼
elf_loader.py
  • symtab 파싱 → 함수명 + 주소
  • stripped → ENDBR64/PUSH RBP 휴리스틱으로 경계 탐지
    │
    ▼
disasm.py (capstone)
  • 함수 바이트를 x86-64 명령어로 디스어셈블
  • JMP/JCC/RET 기준으로 Basic Block 분할
    │
    ▼
cfg.py (networkx)
  • DiGraph로 블록 간 엣지 구성
  • 통계 계산: blocks, edges, CC, longest path
    │
    ├──▶ layout.py (rich)    → 4분할 TUI 렌더링
    │
    └──▶ llm.py (anthropic)  → Claude API 스트리밍
           • JSON 응답 파싱
           • format_parsed() 로 패널 출력
           • results.csv append
```

---

## 문제 해결

### `ANTHROPIC_API_KEY` 오류
- API 키가 설정되지 않은 경우 LLM 패널에 오류 메시지가 표시됩니다
- `--no-llm` 플래그로 API 없이 사용 가능합니다

### 함수가 탐지되지 않는 경우
- 바이너리가 심볼 테이블과 표준 프롤로그 패턴(`PUSH RBP; MOV RBP,RSP`) 모두 없는 경우 발생합니다
- 극단적으로 난독화된 바이너리는 함수 경계를 탐지하기 어렵습니다

### 터미널 너비가 좁은 경우
- 최소 80컬럼을 권장합니다
- rich Layout이 자동으로 공간을 분배하지만, 40컬럼 이하에서는 패널이 겹칠 수 있습니다

### `capstone` 설치 오류 (Windows)
```powershell
pip install capstone --pre
```

---

## 추가 인수 (analyzer.py)

| 인수 | 기본값 | 설명 |
|---|---|---|
| `--category` | `unknown` | 취약점 난이도 (`easy` / `hard`) |
| `--level` | `unknown` | 난독화 레벨 (`none` / `L1` / … / `L1L2L3L4`) |
| `--auto-select` | (플래그) | 함수 자동 선택 후 LLM 분석 → CSV 저장 후 종료 |

### `--auto-select` 함수 선택 기준

1. 심볼 이름이 `vuln` 또는 `process_input` 인 함수 우선
2. 없으면 기본 블록 수가 가장 많은 함수 (가장 복잡한 함수)

```bash
# 단일 바이너리 자동 분석 예시
python analyzer/analyzer.py \
  --binary experiment/easy/target_easy_L1L2L3 \
  --category easy \
  --level L1L2L3 \
  --auto-select
```

---

## 실험 자동화 (`run_analysis.sh`)

`experiment/` 디렉토리 아래 ELF 바이너리를 최대 10개 자동 분석합니다.

```
experiment/
├── easy/
│   ├── target_easy_none
│   ├── target_easy_L1
│   ├── target_easy_L1L2
│   ├── target_easy_L1L2L3
│   └── target_easy_L1L2L3L4
└── hard/
    ├── target_hard_none
    ├── target_hard_L1
    ├── target_hard_L1L2
    ├── target_hard_L1L2L3
    └── target_hard_L1L2L3L4
```

**카테고리 파싱**: 부모 디렉토리 이름(`easy`/`hard`) 또는 파일명에서 자동 감지  
**레벨 파싱**: 파일명에서 `L1L2L3L4` > `L1L2L3` > `L1L2` > `L1` > `none` 순으로 탐지

```bash
# WSL / Linux 에서 실행
chmod +x run_analysis.sh
./run_analysis.sh
# → 완료 후: "results.csv 업데이트 완료" 출력
```

---

## 그래프 생성 (`plot_results.py`)

```bash
pip install matplotlib pandas   # 또는 requirements.txt 일괄 설치
python plot_results.py --input results.csv
```

생성 파일:

| 파일 | 내용 |
|---|---|
| `results_vuln_detection.png` | LLM 취약점 탐지율 vs 난독화 레벨 (easy=파란색, hard=빨간색) |
| `results_cfg_complexity.png` | Cyclomatic Complexity 평균 vs 난독화 레벨 |

---

## 요구 사항

- Python 3.10 이상
- x86-64 ELF 바이너리 (Linux ELF, ARM ELF는 미지원)
- 터미널: VT100 이상 지원 (Windows Terminal, iTerm2, WSL 권장)
- `run_analysis.sh` 실행 환경: bash (WSL / Linux)
