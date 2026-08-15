from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class ProcessResult:
    args: list[str]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class ProcessRunner:
    def run(self, args: list[str], timeout_seconds: int = 300, cwd: str | None = None) -> ProcessResult:
        try:
            completed = subprocess.run(
                args,
                cwd=cwd,
                timeout=timeout_seconds,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                check=False,
            )
            return ProcessResult(args=args, exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
        except FileNotFoundError as exc:
            return ProcessResult(args=args, exit_code=127, stdout="", stderr=str(exc))
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            return ProcessResult(args=args, exit_code=124, stdout=stdout, stderr=stderr or "Process timed out", timed_out=True)
