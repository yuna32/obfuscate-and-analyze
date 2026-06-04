from __future__ import annotations
import json
import os
from typing import Generator, Optional

import anthropic

SYSTEM_PROMPT = (
    "You are a binary reverse engineering expert specializing in obfuscated ELF analysis. "
    "Always respond in the exact JSON format requested by the user."
)

USER_PROMPT_TEMPLATE = """\
다음은 x86-64 ELF 바이너리에서 추출한 함수의 디스어셈블입니다.
난독화(junk instruction, opaque predicate, control flow flattening,
string encryption 등)가 적용되어 있을 수 있습니다.

{disassembly}

아래 JSON 형식으로만 응답하세요. 마크다운 코드블록 없이 JSON만 출력하세요:
{{
  "summary": "함수 기능 한국어 설명 (2~3문장)",
  "vulnerability": {{
    "found": true or false,
    "type": "취약점 종류 또는 null",
    "detail": "취약점 설명 또는 null"
  }},
  "obfuscation": {{
    "detected": true or false,
    "techniques": ["탐지된 기법 목록"] or []
  }}
}}"""


def _get_client() -> anthropic.Anthropic:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    return anthropic.Anthropic(api_key=api_key)


def stream_analysis(disassembly: str) -> Generator[str, None, None]:
    client = _get_client()
    prompt = USER_PROMPT_TEMPLATE.format(disassembly=disassembly)

    with client.messages.stream(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        for text in stream.text_stream:
            yield text


def parse_response(raw: str) -> Optional[dict]:
    text = raw.strip()
    # 코드펜스 제거
    if text.startswith("```"):
        lines = text.splitlines()
        inner = []
        in_block = False
        for line in lines:
            if line.strip().startswith("```"):
                in_block = not in_block
                continue
            if in_block:
                inner.append(line)
        text = "\n".join(inner).strip()
    # JSON 파싱
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass
    return None


def format_parsed(data: dict) -> str:
    lines: list[str] = []

    lines.append("[bold cyan]┌─[ 요약 ]──────────────────────────────[/bold cyan]")
    lines.append(data.get("summary", "N/A"))
    lines.append("")

    vuln = data.get("vulnerability", {})
    found = vuln.get("found", False)
    if found:
        lines.append("[bold red]┌─[ 취약점 ] FOUND ─────────────────────[/bold red]")
        lines.append(f"  종류: {vuln.get('type', 'N/A')}")
        lines.append(f"  설명: {vuln.get('detail', 'N/A')}")
    else:
        lines.append("[bold green]┌─[ 취약점 ] 없음 ──────────────────────[/bold green]")
    lines.append("")

    obf = data.get("obfuscation", {})
    detected = obf.get("detected", False)
    if detected:
        lines.append("[bold yellow]┌─[ 난독화 ] 탐지됨 ────────────────────[/bold yellow]")
        for t in obf.get("techniques", []):
            lines.append(f"  • {t}")
    else:
        lines.append("[bold green]┌─[ 난독화 ] 없음 ──────────────────────[/bold green]")

    return "\n".join(lines)
