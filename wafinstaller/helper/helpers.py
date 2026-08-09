import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from django.conf import settings
from packaging.version import InvalidVersion, Version

from wafinstaller.models import CrsVersion
from wafinstaller.helper.adapters import detect_crs_version


# ---------- Generic utilities ----------

def parse_datetime(dt_str: str):
    """Parse ISO-like datetime string to datetime; return original string on failure."""
    try:
        return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return dt_str


def normalize_version(version: Optional[str]) -> Optional[str]:
    """Return a canonical PEP 440 version for a CRS release tag."""
    if not version:
        return None
    value = version.strip()
    if value[:1].lower() == "v":
        value = value[1:]
    try:
        return str(Version(value))
    except InvalidVersion:
        return None


def parse_crs_version(version: Optional[str]) -> Optional[Version]:
    """Parse a CRS tag, accepting values with or without a leading ``v``."""
    normalized = normalize_version(version)
    if normalized is None:
        return None
    return Version(normalized)


def select_latest_crs_version(tags: Iterable[str]) -> Optional[str]:
    """Select the highest stable CRS version, independently of publish time."""
    versions = [parsed for tag in tags if (parsed := parse_crs_version(tag))]
    stable_versions = [
        version
        for version in versions
        if not version.is_prerelease and not version.is_devrelease
    ]
    return str(max(stable_versions)) if stable_versions else None


def compare_crs_versions(left: Optional[str], right: Optional[str]) -> Optional[int]:
    """Compare two CRS versions, returning -1, 0, 1, or None if unknown."""
    left_version = parse_crs_version(left)
    right_version = parse_crs_version(right)
    if left_version is None or right_version is None:
        return None
    return (left_version > right_version) - (left_version < right_version)


def get_crs_version_status(
    installed: Optional[str], latest: Optional[str]
) -> str:
    """Describe the relationship between active and catalog CRS versions."""
    comparison = compare_crs_versions(installed, latest)
    if comparison is None:
        return "unknown"
    if comparison < 0:
        return "update_available"
    if comparison > 0:
        return "catalog_behind"
    return "up_to_date"


def is_crs_update_available(
    installed: Optional[str], latest: Optional[str]
) -> bool:
    return get_crs_version_status(installed, latest) == "update_available"


def get_latest_crs_version() -> Optional[str]:
    """Return the highest stable CRS version stored in the local catalog."""
    try:
        return select_latest_crs_version(
            CrsVersion.objects.values_list("tag", flat=True)
        )
    except Exception:
        return None


def get_installed_crs_version() -> Optional[str]:
    """Detect installed CRS version from the system and normalize it."""
    version = detect_crs_version()
    return normalize_version(version) if version else None


# ---------- Script runners ----------

def _scripts_dir() -> Path:
    """
    Locate the scripts directory reliably.
    Priority:
      1) <BASE_DIR>/scripts            (preferred)
      2) <app_root>/../scripts         (fallback if module moved around)
    """
    base_scripts = (Path(settings.BASE_DIR) / "scripts").resolve()
    if base_scripts.exists():
        return base_scripts

    app_root = Path(__file__).resolve().parents[1]  # .../wafinstaller
    fallback = (app_root.parent / "scripts").resolve()
    return fallback


def _safe_json_loads(s: str) -> Dict[str, Any]:
    try:
        return json.loads(s)
    except Exception:
        return {}


def run_basic_script() -> Dict[str, Any]:
    """Run scripts/basic.sh to get server/nginx/apache/waf state."""
    script_path = (_scripts_dir() / "basic.sh")
    if not script_path.exists():
        return {
            "server": "none",
            "nginx": {"exit_code": 1, "version": ""},
            "apache": {"exit_code": 1, "version": ""},
            "waf": {"exit_code": 1, "version": ""},
            "error": f"script not found: {script_path}",
        }

    try:
        result = subprocess.run(
            ["/bin/bash", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        data = _safe_json_loads((result.stdout or "").strip())
        # Ensure minimum shape even if script returns partial data
        data.setdefault("server", "none")
        data.setdefault("nginx", {"exit_code": 1, "version": ""})
        data.setdefault("apache", {"exit_code": 1, "version": ""})
        data.setdefault("waf", {"exit_code": 1, "version": ""})
        # Attach exit code/stderr for debugging if available
        data.setdefault("_exit_code", result.returncode)
        if result.stderr:
            data.setdefault("_stderr", result.stderr.strip())
        return data
    except Exception as e:
        return {
            "server": "none",
            "nginx": {"exit_code": 1, "version": ""},
            "apache": {"exit_code": 1, "version": ""},
            "waf": {"exit_code": 1, "version": ""},
            "error": f"exception: {e}",
        }


def run_updatecrs_script() -> Tuple[int, List[str]]:
    """Run scripts/updatecrs.sh and return (exit_code, log_lines)."""
    script_path = (_scripts_dir() / "updatecrs.sh")
    if not script_path.exists():
        return 1, [f"script not found: {script_path}"]

    log: List[str] = []
    try:
        process = subprocess.Popen(
            ["/bin/bash", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        assert process.stdout is not None
        for line in iter(process.stdout.readline, ""):
            log.append(line.rstrip("\n"))
        process.stdout.close()
        process.wait()
        return process.returncode, log
    except Exception as e:
        return 1, [f"Error: {e}"]


def run_switch_version_script(version: str, reinstall: bool = False) -> Tuple[int, str]:
    """Run scripts/switch_crs_version.sh <version> [--reinstall] and return (exit_code, message)."""
    script_path = (_scripts_dir() / "switch_crs_version.sh")
    if not script_path.exists():
        return 1, f"script not found: {script_path}"

    cmd = ["/bin/bash", str(script_path), version]
    if reinstall:
        cmd.append("--reinstall")
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return proc.returncode, (proc.stderr.strip() or proc.stdout.strip())
    except Exception as e:
        return 1, f"Error: {e}"
