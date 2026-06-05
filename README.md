# obfuscate-and-analyze

> **ELF 바이너리 난독화 기법 구현과 LLM 기반 역분석 한계 실험**  
> *"코드를 숨기는 자와 읽는 자 — 자동화 분석의 경계"*

---

## 개요

본 프로젝트는 x86-64 ELF 바이너리에 4단계 난독화 레이어를 직접 구현하고, Claude API를 활용한 LLM 기반 역분석 도구를 제작하여 **난독화 기법이 LLM의 취약점 탐지 능력에 미치는 영향을 실험적으로 측정**합니다.

기존 연구들이 "LLM은 난독화 앞에서 무너진다"는 결론을 보여줬다면, 이 프로젝트는 한 발 더 나아가 **어떤 기법이, 어떤 취약점 유형의 탐지를, 어떤 방식으로 무너뜨리는가**를 직접 재현합니다.

---

## 핵심 발견

실험 결과, LLM의 취약점 탐지 실패에는 두 가지 서로 다른 패턴이 존재합니다.

| 패턴 | 난독화 기법 | 취약점 유형 | 실패 메커니즘 |
|---|---|---|---|
| A | Junk instruction (L1) | 패턴 기반 (strcpy BOF) | 루프 구조 인식 방해 → 패턴 매칭 실패 |
| B | Control flow flattening (L3) | 로직 기반 (off-by-one) | 함수 구조 오인 → 구조적 추론 붕괴 |

> **"코드가 길어지면 LLM도 길을 잃는다 / 구조가 무너지면 추론도 무너진다"**

---

## 프로젝트 구성

```
hide-and-pwn/
├── obfuscator/          # ELF 난독화기
│   ├── obfuscator.py    # CLI 진입점
│   ├── core/            # ELF 파싱, 디스어셈블, 패치 유틸
│   └── transforms/      # L1~L4 난독화 레이어
├── analyzer/            # LLM 기반 역분석 TUI
│   ├── analyzer.py      # CLI 진입점
│   ├── core/            # ELF 로더, CFG, LLM 연동
│   └── ui/              # rich 기반 레이아웃
├── target_easy.c        # 실험 타깃 — strcpy BOF
├── target_hard.c        # 실험 타깃 — off-by-one BOF
├── run_experiment.sh    # 바이너리 10개 자동 생성
├── run_analysis.sh      # LLM 분석 자동 실행
└── plot_results.py      # 실험 결과 그래프 생성
```

---

## 난독화 레이어

| 레이어 | 기법 | 설명 |
|---|---|---|
| L1 | Junk instruction | 기본 블록 경계에 NOP·MOV rax,rax 등 삽입 |
| L2 | Opaque predicate | 항상 참/거짓인 조건문으로 가짜 분기 생성 |
| L3 | Control flow flattening | 모든 기본 블록을 dispatcher 루프로 평탄화 |
| L4 | String encryption | .rodata 문자열 XOR 암호화 + .init_array stub 등록 |

레이어는 독립적으로 조합 가능합니다.

```bash
python obfuscator.py --input ./target --output ./target_obf \
    --levels L1,L2,L3,L4 --verify --verify-args "test"
```

---

## 역분석 도구

Claude API와 연동된 터미널 기반 TUI입니다. 디스어셈블 뷰, CFG 복잡도 측정, LLM 실시간 분석을 한 화면에서 제공합니다.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
cd analyzer
python -m analyzer.analyzer --binary ./target_obf --auto-select
```

분석 결과는 `results.csv`에 자동 누적됩니다.

---

## 실험 재현

```bash
# 1. 환경 세팅
python3 -m venv .venv && source .venv/bin/activate
pip install -r obfuscator/requirements.txt
pip install -r analyzer/requirements.txt

# 2. 난독화 바이너리 10개 생성 (none / L1 / L1L2 / L1L2L3 / L1L2L3L4 × 2 타깃)
bash run_experiment.sh

# 3. LLM 분석 실행 (반복 횟수만큼)
bash run_analysis.sh

# 4. 결과 그래프 생성
python plot_results.py --input results.csv
```

---

## 실험 결과

10회 반복 측정 기준 LLM 취약점 탐지율:

```
탐지율(%)
100 ─ ●────────────────●────●
      |                      Easy (strcpy BOF)
 71 ─      ●────●
                              
100 ─ ●────●────●
                      Hard (off-by-one BOF)
 92 ─           ●────●────●
      none  L1  L1L2  L1L2L3  L1L2L3L4
```

- Easy: L1 구간에서 71%로 하락 → Junk instruction이 루프 패턴 인식 방해
- Hard: L1L2L3 구간부터 92%로 고착 → CFF 적용 시 함수를 dispatcher로 오인

---

## 기술 스택

**난독화기**
- `capstone` — 디스어셈블
- `keystone-engine` — 재어셈블
- `pyelftools` — ELF 파싱 및 패치

**역분석 도구**
- `anthropic` — Claude API 스트리밍
- `rich` — TUI 레이아웃
- `networkx` — CFG 구성 및 복잡도 계산
- `matplotlib` / `pandas` — 결과 시각화

---

## 관련 연구

- *"Digital Camouflage": The LLVM Challenge in LLM-Based Malware Detection* — TU Berlin / Fraunhofer, 2025
- *The Cost of Understanding: LLM-Driven Reverse Engineering vs Iterative LLM Obfuscation* — Elastic Security Labs, 2026
- *Can LLMs Deobfuscate Binary Code?* — arXiv, 2026

---

## 한계 및 후속 연구 방향

- L3 (CFF)는 CALL 포함 함수를 안전상 스킵 → 실행 무결성과 완전한 난독화 간 트레이드오프 존재
- 샘플이 바이너리 2종 × 10회 반복으로 통계적 엄밀성 제한
- 후속: 동적 분석 + LLM 하이브리드, 난독화 인식 특화 fine-tuning

---

## License

MIT
