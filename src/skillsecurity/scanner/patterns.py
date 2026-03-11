"""Dangerous pattern definitions for Python and JS/TS."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class DangerousPattern:
    id: str
    pattern: re.Pattern[str]
    category: str
    severity: str
    description: str
    language: str  # "python", "javascript", "all"
    detected_permission: str = ""


PYTHON_PATTERNS = [
    DangerousPattern(
        id="py-eval",
        pattern=re.compile(r"\beval\s*\("),
        category="dynamic_code_execution",
        severity="critical",
        description="Use of eval() — arbitrary code execution",
        language="python",
        detected_permission="shell",
    ),
    DangerousPattern(
        id="py-exec",
        pattern=re.compile(r"\bexec\s*\("),
        category="dynamic_code_execution",
        severity="critical",
        description="Use of exec() — arbitrary code execution",
        language="python",
        detected_permission="shell",
    ),
    DangerousPattern(
        id="py-subprocess",
        pattern=re.compile(r"\bsubprocess\.(call|run|Popen|check_output|check_call)\s*\("),
        category="shell_execution",
        severity="high",
        description="Subprocess execution",
        language="python",
        detected_permission="shell",
    ),
    DangerousPattern(
        id="py-os-system",
        pattern=re.compile(r"\bos\.system\s*\("),
        category="shell_execution",
        severity="high",
        description="os.system() call",
        language="python",
        detected_permission="shell",
    ),
    DangerousPattern(
        id="py-os-popen",
        pattern=re.compile(r"\bos\.popen\s*\("),
        category="shell_execution",
        severity="high",
        description="os.popen() call",
        language="python",
        detected_permission="shell",
    ),
    DangerousPattern(
        id="py-data-exfil",
        pattern=re.compile(r"requests\.(post|put)\s*\(.*os\.environ"),
        category="data_exfiltration",
        severity="critical",
        description="Sending environment variables over HTTP",
        language="python",
        detected_permission="network.write",
    ),
    DangerousPattern(
        id="py-env-access",
        pattern=re.compile(r"\bos\.environ\b"),
        category="env_access",
        severity="medium",
        description="Access to environment variables",
        language="python",
        detected_permission="env.read",
    ),
    DangerousPattern(
        id="py-file-write",
        pattern=re.compile(r"\bopen\s*\(.*['\"]w['\"]"),
        category="file_write",
        severity="medium",
        description="File write operation",
        language="python",
        detected_permission="file.write",
    ),
    DangerousPattern(
        id="py-pickle",
        pattern=re.compile(r"\bpickle\.loads?\s*\("),
        category="deserialization",
        severity="high",
        description="Pickle deserialization — code execution risk",
        language="python",
        detected_permission="shell",
    ),
    DangerousPattern(
        id="py-compile",
        pattern=re.compile(r"\bcompile\s*\(.*exec"),
        category="dynamic_code_execution",
        severity="critical",
        description="Dynamic code compilation",
        language="python",
        detected_permission="shell",
    ),
    DangerousPattern(
        id="py-import-importlib",
        pattern=re.compile(r"\b__import__\s*\(|importlib\.import_module\s*\("),
        category="dynamic_import",
        severity="high",
        description="Dynamic module import",
        language="python",
        detected_permission="shell",
    ),
    DangerousPattern(
        id="py-reverse-shell",
        pattern=re.compile(r"socket\.socket\s*\(.*\.connect\s*\("),
        category="reverse_shell",
        severity="critical",
        description="Socket connection — possible reverse shell",
        language="python",
        detected_permission="network.write",
    ),
    DangerousPattern(
        id="py-base64-obfuscation",
        pattern=re.compile(r"base64\.(b64decode|decodebytes)\s*\(.*\bexec\b"),
        category="code_obfuscation",
        severity="critical",
        description="Base64-encoded code execution",
        language="python",
        detected_permission="shell",
    ),
]

JS_PATTERNS = [
    DangerousPattern(
        id="js-eval",
        pattern=re.compile(r"\beval\s*\("),
        category="dynamic_code_execution",
        severity="critical",
        description="Use of eval() — arbitrary code execution",
        language="javascript",
        detected_permission="shell",
    ),
    DangerousPattern(
        id="js-function-constructor",
        pattern=re.compile(r"\bnew\s+Function\s*\("),
        category="dynamic_code_execution",
        severity="critical",
        description="new Function() — dynamic code execution",
        language="javascript",
        detected_permission="shell",
    ),
    DangerousPattern(
        id="js-child-process",
        pattern=re.compile(r"require\s*\(\s*['\"]child_process['\"]\s*\)|child_process\.exec"),
        category="shell_execution",
        severity="high",
        description="Child process execution",
        language="javascript",
        detected_permission="shell",
    ),
    DangerousPattern(
        id="js-fs-write",
        pattern=re.compile(r"\bfs\.(writeFile|appendFile|createWriteStream)\s*\("),
        category="file_write",
        severity="medium",
        description="File write operation",
        language="javascript",
        detected_permission="file.write",
    ),
    DangerousPattern(
        id="js-fetch-env",
        pattern=re.compile(r"fetch\s*\(.*process\.env"),
        category="data_exfiltration",
        severity="critical",
        description="Sending environment data via fetch",
        language="javascript",
        detected_permission="network.write",
    ),
    DangerousPattern(
        id="js-env-access",
        pattern=re.compile(r"\bprocess\.env\b"),
        category="env_access",
        severity="medium",
        description="Access to environment variables",
        language="javascript",
        detected_permission="env.read",
    ),
]

ALL_PATTERNS = PYTHON_PATTERNS + JS_PATTERNS

LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
}


def get_patterns_for_language(language: str) -> list[DangerousPattern]:
    return [p for p in ALL_PATTERNS if p.language == language or p.language == "all"]
