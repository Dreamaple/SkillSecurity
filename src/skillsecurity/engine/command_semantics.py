"""Command semantic checks that go beyond regex-only policy matching."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from skillsecurity.models.decision import Decision, RuleRef
from skillsecurity.models.rule import Action, Severity
from skillsecurity.models.tool_call import ToolCall, ToolType

_OUTPUT_FLAG_NAMES = {
    "-o",
    "--output",
    "--out",
    "--destination",
    "--dest",
    "--file",
    "--config",
}

_SENSITIVE_PATH_PREFIXES_UNIX = (
    "/etc",
    "/system",
    "/boot",
    "/sbin",
    "/usr/sbin",
    "/root",
)
_SENSITIVE_PATH_PREFIXES_WINDOWS = (
    "c:\\windows",
    "c:\\program files",
)
_SENSITIVE_PATH_CONTAINS = (
    ".ssh",
    ".aws",
    ".gnupg",
)


class CommandSemanticsGuard:
    """Detects risky command semantics (output-path writes, redirection targets)."""

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled

    def check(self, tool_call: ToolCall) -> Decision | None:
        if not self._enabled or tool_call.tool_type != ToolType.SHELL:
            return None
        command = str(tool_call.params.get("command", "")).strip()
        if not command:
            return None

        redir_target = self._extract_redirection_target(command)
        if redir_target and self._is_sensitive_path(redir_target):
            return Decision(
                action=Action.BLOCK,
                reason=f"Shell redirection targets sensitive path '{redir_target}'",
                severity=Severity.CRITICAL,
                rule_matched=RuleRef(
                    id="command-semantics:redirection-sensitive-path",
                    description="Command semantic guard",
                ),
                suggestions=["Redirect output to a temporary safe directory first."],
            )

        args = self._split_command(command)
        output_targets = self._extract_output_targets(args)
        for target in output_targets:
            if self._is_sensitive_path(target):
                return Decision(
                    action=Action.BLOCK,
                    reason=f"Command output parameter targets sensitive path '{target}'",
                    severity=Severity.CRITICAL,
                    rule_matched=RuleRef(
                        id="command-semantics:output-sensitive-path",
                        description="Command semantic guard",
                    ),
                    suggestions=["Avoid writing command outputs into system/credential paths."],
                )

        return None

    @staticmethod
    def _split_command(command: str) -> list[str]:
        for posix in (True, False):
            try:
                return shlex.split(command, posix=posix)
            except ValueError:
                continue
        return command.split()

    @staticmethod
    def _extract_output_targets(args: list[str]) -> list[str]:
        targets: list[str] = []
        i = 0
        while i < len(args):
            tok = args[i]
            if tok in _OUTPUT_FLAG_NAMES and i + 1 < len(args):
                targets.append(args[i + 1])
                i += 2
                continue

            if tok.startswith("-o") and len(tok) > 2 and tok != "--output":
                # Detect attached short option payloads such as: -o/tmp/poc
                targets.append(tok[2:])
                i += 1
                continue

            for long_flag in (
                "--output=",
                "--out=",
                "--destination=",
                "--dest=",
                "--file=",
                "--config=",
            ):
                if tok.startswith(long_flag):
                    targets.append(tok[len(long_flag) :])
                    break
            i += 1
        return targets

    @staticmethod
    def _extract_redirection_target(command: str) -> str | None:
        # Capture output redirection target after > or >>.
        m = re.search(r"(?:^|[\s])(>>?|1>|2>|&>)\s*([^\s]+)", command)
        if not m:
            return None
        return m.group(2).strip()

    @staticmethod
    def _is_sensitive_path(path_value: str) -> bool:
        raw = path_value.strip().strip("'\"")
        if not raw:
            return False

        lower_raw = raw.lower()
        if lower_raw.startswith(tuple(_SENSITIVE_PATH_PREFIXES_UNIX)):
            return True
        if lower_raw.startswith(tuple(_SENSITIVE_PATH_PREFIXES_WINDOWS)):
            return True
        if any(seg in lower_raw for seg in _SENSITIVE_PATH_CONTAINS):
            return True

        # Normalize if possible to catch relative paths that resolve to sensitive prefixes.
        try:
            p = Path(raw).expanduser()
            if not p.is_absolute():
                p = (Path.cwd() / p).resolve(strict=False)
            else:
                p = p.resolve(strict=False)
            normalized = str(p).replace("\\", "/").lower()
            if normalized.startswith(_SENSITIVE_PATH_PREFIXES_UNIX):
                return True
            if normalized.startswith(("c:/windows", "c:/program files")):
                return True
            if any(seg in normalized for seg in _SENSITIVE_PATH_CONTAINS):
                return True
        except OSError:
            return False
        return False
