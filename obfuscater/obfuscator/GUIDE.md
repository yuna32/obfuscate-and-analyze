# ELF Obfuscator — 사용 가이드

x86-64 ELF 바이너리에 난독화 레이어를 선택 적용하는 CLI 도구.  
난독화 후에도 **실행 무결성**이 보장된다.

---

## 목차

1. [환경 설정](#1-환경-설정)
2. [테스트 바이너리 빌드](#2-테스트-바이너리-빌드)
3. [CLI 레퍼런스](#3-cli-레퍼런스)
4. [레이어별 사용 예시](#4-레이어별-사용-예시)
5. [레이어 설계](#5-레이어-설계)
   - [L1 — Junk Instruction 삽입](#l1--junk-instruction-삽입)
   - [L2 — Opaque Predicate 삽입](#l2--opaque-predicate-삽입)
   - [L3 — Control Flow Flattening (스텁)](#l3--control-flow-flattening-스텁)
   - [L4 — String Encryption](#l4--string-encryption)
6. [파일 구조](#6-파일-구조)
7. [공통 제약 및 주의사항](#7-공통-제약-및-주의사항)

---

## 1. 환경 설정

**요구사항:** Python 3.10+, Linux 또는 WSL (x86-64 ELF 타깃)

```bash
# 프로젝트 루트(obfuscator/ 상위 디렉터리)에서
python3 -m venv .venv
source .venv/bin/activate          # Windows WSL: .venv/bin/activate
pip install -r obfuscator/requirements.txt
```

`requirements.txt` 내용:
```
capstone>=5.0.0
keystone-engine>=0.9.2
pyelftools>=0.31
```

---

## 2. 테스트 바이너리 빌드

프로젝트에 포함된 `target.c`를 사용한다.

```bash
gcc -o target target.c -no-pie -fno-stack-protector -g
```

플래그 설명:

| 플래그 | 이유 |
|--------|------|
| `-no-pie` | 절대 가상 주소 고정 (ASLR 비활성화) — L4 stub이 하드코딩된 vaddr 사용 |
| `-fno-stack-protector` | 스택 카나리 제거 — 테스트 단순화 |
| `-g` | 디버그 심볼 포함 — 분석 편의 |

---

## 3. CLI 레퍼런스

```
python3 obfuscator/obfuscator.py \
    --input  <원본 ELF>  \
    --output <출력 ELF>  \
    --levels <레이어 목록>
    [--verify]
    [--verify-args <인자>]
    [--dry-run]
    [--seed <정수>]
    [--verbose]
```

### 옵션 상세

| 옵션 | 설명 |
|------|------|
| `--input`, `-i` | 입력 ELF 바이너리 경로 |
| `--output`, `-o` | 출력 ELF 바이너리 경로 |
| `--levels`, `-l` | 쉼표 구분 레이어 목록. 예: `L1,L2,L4` |
| `--verify` | 난독화 후 원본과 stdout/stderr/종료코드 자동 비교 |
| `--verify-args` | `--verify` 실행 시 바이너리에 전달할 인자 (기본값: `World`) |
| `--dry-run` | 실제 파일 쓰기 없이 적용 결과 요약만 출력 |
| `--seed` | 랜덤 시드 — 재현 가능한 난독화 |
| `--verbose`, `-v` | DEBUG 레벨 로그 출력 |

### 에러 안전성

출력 파일은 임시 파일에 먼저 작성한 뒤 원자적으로 교체한다.  
변환 중 예외가 발생해도 원본 바이너리는 보존된다.

---

## 4. 레이어별 사용 예시

```bash
# L1만 적용
python3 obfuscator/obfuscator.py -i target -o target_l1 --levels L1

# L2만 적용
python3 obfuscator/obfuscator.py -i target -o target_l2 --levels L2

# L4만 적용 + 실행 무결성 검증
python3 obfuscator/obfuscator.py -i target -o target_l4 \
    --levels L4 --verify --verify-args World

# L1 + L2 + L4 조합 + 시드 고정
python3 obfuscator/obfuscator.py -i target -o target_all \
    --levels L1,L2,L4 --seed 42 --verify --verify-args World

# 실제 쓰기 없이 결과 미리보기
python3 obfuscator/obfuscator.py -i target -o /dev/null \
    --levels L1,L2,L4 --dry-run

# L3는 NotImplementedError를 발생시키므로 단독 사용 시 경고 출력 후 스킵됨
python3 obfuscator/obfuscator.py -i target -o target_l3 --levels L3
```

---

## 5. 레이어 설계

### L1 — Junk Instruction 삽입

**목적:** 디스어셈블리 가독성 저하. NOP 패딩을 의미 있어 보이는 인스트럭션으로 교체한다.

#### 동작 원리

gcc는 함수 사이 정렬(align)을 위해 NOP 패딩을 삽입한다. L1은 이 패딩을 탐지하고 같은 크기의 inert 인스트럭션 시퀀스로 교체한다.

```
Before:
  ret
  66 2e 0f 1f 84 00 ...  ← 10-byte NOP (alignment padding)
  <next function>

After L1:
  ret
  48 89 C0               ← MOV rax, rax  (3 bytes)
  48 89 D2               ← MOV rdx, rdx  (3 bytes)
  66 90                  ← 2-byte NOP    (2 bytes)
  90                     ← NOP           (1 bytes)
  90                     ← NOP           (1 bytes)
  <next function>
```

#### 사용 junk 시퀀스

| 바이트 | 인스트럭션 | 크기 |
|--------|------------|------|
| `90` | `NOP` | 1 |
| `66 90` | `NOP` (2-byte) | 2 |
| `48 89 C0` | `MOV rax, rax` | 3 |
| `48 89 D2` | `MOV rdx, rdx` | 3 |
| `48 87 C0` | `XCHG rax, rax` | 3 |
| `48 8D 40 00` | `LEA rax, [rax+0]` | 4 |

#### 특성

- **섹션 크기 변화 없음** — NOP과 동일 바이트 수로 교체
- **브랜치 오프셋 재계산 불필요** — 주소 이동 없음
- **실행 무결성 보장** — 모든 교체 인스트럭션이 semantically inert

---

### L2 — Opaque Predicate 삽입

**목적:** 데드 코드 분기를 삽입해 정적 분석을 혼란시킨다.

#### 삽입 패턴 (N 바이트 NOP 공간, N ≥ 11)

```
; 항상 ZF=1이므로 JNZ는 절대 실행되지 않음
XOR rdx, rdx     ; 48 31 D2  (3 bytes) — rdx = 0
TEST rdx, rdx    ; 48 85 D2  (3 bytes) — ZF = 1 (항상)
JNZ +2           ; 75 02     (2 bytes) — 절대 taken 안 됨 → fake_target
JMP +junk_len    ; EB XX     (2 bytes) — 항상 taken → real_next
[junk]           ;           (N-10 bytes) ← fake_target (dead code)
; real_next: 원래 코드 계속
```

분석가는 `JNZ`가 live branch처럼 보여 `fake_target` 내 junk 코드를 분석하게 된다.

#### 특성

- NOP 패딩 ≥ 11 바이트인 위치에만 적용 (L1 적용 후 NOP이 없으면 스킵)
- L1보다 먼저 적용하는 것을 권장 (`L2,L1` 순서)
- 섹션 크기 변화 없음

---

### L3 — Control Flow Flattening

**목적:** 함수의 제어 흐름을 state-machine dispatcher로 평탄화하여 정적 분석을 혼란시킨다.

#### 동작 원리

```
[원래 흐름]                [평탄화 후]
  block_0 ──→ block_1        trampoline: JMP block_0_new
  block_0 ──→ block_3        dispatcher: mov eax,[state_var]
  block_1 ──→ block_2                    cmp eax,0; jz block_0
  block_2: ret                           cmp eax,1; jz block_1 ...
                             block_0 (복사): ... ; mov [state],1; jmp disp
                             block_1 (복사): ... ; mov [state],2; jmp disp
                             block_2 (복사): ret
```

#### 전체 흐름

```
[빌드 타임]
1. .symtab에서 STT_FUNC 심볼 열거 (size=0인 경우 인접 심볼로 크기 추론)
2. 각 함수에 대해:
   a. capstone detail 모드로 디스어셈블 → 기본 블록 분리
   b. 조건 검사: 블록 수 ≤ 10, CALL 포함 블록 없음
   c. state_id 할당 (블록 순서 = 0,1,2,...)
   d. 레이아웃 계산: [state_var 4B][dispatcher][block_0][block_1]...
   e. 각 블록 복사 → .text PT_LOAD 슬랙 공간
      - RIP-relative 명령어: displacement 재계산
      - 블록 terminator 교체:
          jmp target_inside  → mov [state],N ; jmp dispatcher
          jcc target_inside  → near_jcc +22 ; false_path ; true_path
          ret / jmp *reg     → 그대로 유지
   f. 원본 함수 시작 5바이트 → JMP trampoline (슬랙의 block_0로)
3. text PT_LOAD p_flags |= PF_W (state_var 런타임 쓰기 허용)
4. text PT_LOAD p_filesz / p_memsz 확장

[런타임]
5. trampoline이 실행되면 block_0_new로 점프
6. 각 블록 실행 후 state 갱신 → dispatcher로 복귀
7. dispatcher가 state 읽어 다음 블록으로 분기
```

#### 슬랙 레이아웃 (함수 1개 기준)

```
slack_vaddr + 0x00 : state_var (uint32, 4 bytes)
slack_vaddr + 0x04 : dispatcher
                       mov eax, [rip+rel]   ; 6 bytes
                       cmp eax, 0           ; 3 bytes  ┐ per block
                       jz  block_0_vaddr    ; 6 bytes  ┘
                       ...
                       ud2                  ; 2 bytes (unreachable)
slack_vaddr + 0x04+D: block_0 (수정된 복사본)
                      block_1 ...
```

#### 특성

- **섹션 크기 변화 없음** — 원본 .text 섹션은 trampoline 5바이트 외 불변
- **슬랙 공간 공유 가능** — L4와 순서 무관하게 각자 p_filesz를 읽어 이어 씀
- **적용 범위**: CALL 없는 함수, 블록 수 ≤ 10 (target.c 기준: `deregister_tm_clones`, `register_tm_clones` 2개 플래트닝)
- **fallback**: 조건 불만족 함수는 경고 후 스킵, 나머지 함수에 계속 적용

---

### L4 — String Encryption

**목적:** `.rodata` 내 문자열을 바이너리에서 grep 불가능하게 XOR 암호화하고, 런타임에 복호화한다.

#### 전체 흐름

```
[빌드 타임 — obfuscator]
1. .rodata 스캔 → NULL-terminated 문자열 탐지
2. 각 문자열을 랜덤 1-byte XOR 키로 암호화 (파일 내 in-place)
3. 복호화 메타데이터 테이블 생성
4. 복호화 stub 핸드 어셈블 (x86-64 machine code)
5. stub + 테이블을 .text PT_LOAD 슬랙 공간에 배치 (파일 zero-padding 덮어쓰기)
6. .text PT_LOAD의 p_filesz / p_memsz 확장
7. .rodata PT_LOAD p_flags에 PF_W 추가 (런타임 쓰기 허용)
8. .init_array[0] 교체 → stub ptr (기존 함수는 stub 내부에서 체이닝 호출)

[런타임 — ELF loader]
9. .init_array 실행 → stub 호출 (main() 이전)
10. stub: 원본 init 함수 호출 → 테이블 순회하며 XOR 복호화
11. main() 실행 → printf 등이 평문 문자열 참조
```

#### 테이블 구조 (엔트리당 16 bytes)

```c
struct decrypt_entry {
    uint64_t vaddr;   // 암호화된 문자열의 가상 주소
    uint32_t length;  // NULL 제외 바이트 수
    uint8_t  key;     // XOR 키
    uint8_t  pad[3];  // 정렬 패딩
};
// 마지막 엔트리: vaddr == 0 (sentinel)
```

#### ELF 패치 전략 (삽입 없는 in-place 방식)

```
파일 레이아웃 (패치 전):
  [0x1000] text PT_LOAD content (0x1FD bytes)
  [0x11FD] ← zero padding ← (0xE03 bytes 여유)
  [0x2000] rodata PT_LOAD content

파일 레이아웃 (패치 후):
  [0x1000] text PT_LOAD content (변경 없음)
  [0x11FD] decrypt table (48 bytes)
  [0x122D] decrypt stub (89 bytes)
  [0x1286] zero padding (남은 공간)
  [0x2000] rodata PT_LOAD (XOR 암호화된 문자열)
```

#### stub 레지스터 레이아웃

```
rbx  = 현재 테이블 엔트리 포인터
r12  = 문자열 가상 주소 (entry.vaddr)
r13  = 문자열 길이 (entry.length)
r14b = XOR 키 (entry.key)
r15  = 바이트 인덱스
```

#### 특성

- `.text` 섹션 크기 변화 없음 (PT_LOAD만 확장)
- 섹션 헤더 테이블 이동 없음 → 기존 도구 호환 유지
- `.rodata` PF_W 패치: RELRO 적용 전에 stub이 실행되므로 안전
- stub 핸드 어셈블: keystone 의존성 없이 REX prefix 직접 계산

---

## 6. 파일 구조

```
obfuscator/
├── obfuscator.py          CLI 진입점, 파이프라인 조율, --verify / --dry-run
├── requirements.txt
├── GUIDE.md               ← 이 파일
├── core/
│   ├── __init__.py
│   ├── elf_parser.py      pyelftools 기반 ELF 파싱 (SectionInfo, ELFInfo)
│   ├── disasm.py          capstone 기반 디스어셈블, BasicBlock 추출
│   ├── asm.py             keystone 어셈블 헬퍼 (assemble, assemble_insn)
│   └── patcher.py         섹션/헤더 패치 유틸리티
└── transforms/
    ├── __init__.py        레이어 레지스트리 (REGISTRY dict)
    ├── base.py            Transform 추상 클래스 (apply → _apply)
    ├── l1_junk.py         L1: NOP 교체
    ├── l2_opaque.py       L2: opaque predicate
    ├── l3_flatten.py      L3: CFF 스텁 (extract_basic_blocks 완성)
    └── l4_strings.py      L4: XOR 암호화 + 런타임 복호화
```

---

## 7. 공통 제약 및 주의사항

### 지원 바이너리 조건

| 조건 | 이유 |
|------|------|
| x86-64 ELF | 유일하게 지원하는 아키텍처 |
| `-no-pie` 권장 | L4가 절대 가상 주소를 stub에 하드코딩 |
| 동적 링크 | `.init_array` 메커니즘 사용 (정적 링크 바이너리는 L4 미지원) |

### L1/L2 효과 한계

NOP 패딩이 적은 바이너리 (최적화 빌드 `-O2`) 는 적용 위치가 줄어든다.  
더 많은 위치에 적용하려면 기본 블록 내부 삽입 + 섹션 확장 방식으로 Phase 2 구현이 필요하다.

### L2가 L1 이후 효과 없는 경우

L1이 NOP을 junk로 채우면 L2가 찾을 NOP(≥11 bytes) 공간이 없어진다.  
`L2,L1` 순서로 적용하거나 L2를 단독으로 사용하면 효과가 더 크다.

### L4 적용 후 바이너리 분석

- `strings target_l4` 결과: `"Hello, %s\n"` 등이 보이지 않음 (XOR 암호화)
- `objdump -s --section=.rodata target_l4`: 바이너리 잡음으로 출력
- 실행 시 stub이 복호화 → printf에서 정상 출력
