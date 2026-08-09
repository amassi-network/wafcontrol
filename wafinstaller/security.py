import fcntl
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Optional, Sequence


class ManagedFileError(ValueError):
    """Raised when a requested file is outside a WAFControl-managed directory."""


class DeploymentError(RuntimeError):
    """Raised when validation or reload fails and the previous file is restored."""


def resolve_managed_file(
    base_dir: str,
    filename: str,
    *,
    allowed_suffixes: Iterable[str] = (".conf", ".data"),
    must_exist: bool = True,
) -> Path:
    """Resolve a direct child of ``base_dir`` without allowing path traversal."""
    if not base_dir or not filename or "\x00" in filename:
        raise ManagedFileError("A managed directory and filename are required.")

    name = Path(filename)
    if name.is_absolute() or name.name != filename or "/" in filename or "\\" in filename:
        raise ManagedFileError("Nested or absolute paths are not allowed.")
    if name.suffix not in set(allowed_suffixes):
        raise ManagedFileError("Unsupported managed file type.")

    try:
        base = Path(base_dir).resolve(strict=True)
        candidate = (base / filename).resolve(strict=must_exist)
    except (FileNotFoundError, OSError) as exc:
        raise ManagedFileError("Managed file or directory does not exist.") from exc

    if candidate.parent != base:
        raise ManagedFileError("The requested file is outside the managed directory.")
    if must_exist and not candidate.is_file():
        raise ManagedFileError("The requested managed file does not exist.")
    return candidate


def _write_replacement(path: Path, content: bytes, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.wafcontrol-", dir=str(path.parent)
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def deploy_managed_text(
    path: Path,
    content: str,
    *,
    test_cmd: Optional[Sequence[str]] = None,
    reload_cmd: Optional[Sequence[str]] = None,
) -> bool:
    """Atomically write, validate and reload, restoring the previous file on failure.

    Returns ``False`` when the requested content is already active.
    """
    path = Path(path)
    if not path.is_file():
        raise ManagedFileError("The managed file does not exist.")

    encoded = content.encode("utf-8")
    if len(encoded) > 2 * 1024 * 1024:
        raise ManagedFileError("Managed file content exceeds the 2 MiB limit.")

    lock_path = path.with_name(f".{path.name}.wafcontrol.lock")
    lock_descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        with os.fdopen(lock_descriptor, "r+b") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            previous = path.read_bytes()
            if previous == encoded:
                return False

            mode = stat.S_IMODE(path.stat().st_mode)
            _write_replacement(path, encoded, mode)
            try:
                if test_cmd:
                    subprocess.run(list(test_cmd), check=True, capture_output=True, text=True)
                if reload_cmd:
                    subprocess.run(list(reload_cmd), check=True, capture_output=True, text=True)
            except (OSError, subprocess.CalledProcessError) as exc:
                _write_replacement(path, previous, mode)
                if reload_cmd:
                    try:
                        subprocess.run(
                            list(reload_cmd),
                            check=False,
                            capture_output=True,
                            text=True,
                        )
                    except (OSError, subprocess.SubprocessError):
                        pass
                raise DeploymentError(
                    "Validation or reload failed; the previous file was restored."
                ) from exc
    finally:
        # Keep the lock inode stable so concurrent processes always lock the same file.
        pass

    return True
