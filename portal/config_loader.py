"""Load local native-backend config profiles for Customer Portal.

This helper mirrors the unsafe profile-to-path join that GHSA-3qwq-q9vm-5j42
describes for Spring Cloud Config Server's native filesystem backend. The
dependency upgrade alone does not remove this first-party join.

Do not treat this file as an exploit. The accompanying tests prove the unsafe
behavior with synthetic fixture files under portal/configs only.
"""

from __future__ import annotations

from pathlib import Path


class ConfigLoadError(ValueError):
    """Raised when a profile cannot be loaded safely."""


def resolve_config_path(config_root: Path, profile: str) -> Path:
    """Return the config file for a profile, contained under config_root.

    Rejects absolute paths, parent segments (``..``), null bytes, and any
    resolved path that is not inside the config root.
    """

    if not profile:
        raise ConfigLoadError("profile must be non-empty")
    if "\x00" in profile:
        raise ConfigLoadError("profile must not contain null bytes")

    candidate = Path(profile)
    if candidate.is_absolute():
        raise ConfigLoadError("profile must be a relative path")
    if ".." in candidate.parts:
        raise ConfigLoadError("profile must not contain parent path segments")

    root = config_root.resolve()
    path = (root / f"{profile}.yml").resolve()
    if not path.is_relative_to(root):
        raise ConfigLoadError("profile path escapes config root")
    return path


def load_profile(config_root: Path, profile: str) -> str:
    path = resolve_config_path(config_root, profile)
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigLoadError(f"unable to read profile {profile!r}") from exc


def list_profiles(config_root: Path) -> list[str]:
    return sorted(path.stem for path in config_root.glob("*.yml") if path.is_file())
