"""Configuration loading and validation for LLM Security Scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class ScanConfig(BaseModel):
    """Top-level configuration model for a scan run."""

    target_path: Path = Field(default=Path("."), description="Root path to scan.")
    rules_dirs: list[Path] = Field(
        default_factory=list,
        description="Additional directories to load built-in rules from.",
    )
    exclude_globs: list[str] = Field(
        default_factory=lambda: [
            "**/.git/**",
            "**/node_modules/**",
            "**/__pycache__/**",
            "**/.venv/**",
        ],
        description="Glob patterns for paths to exclude from scanning.",
    )
    enabled_rules: list[str] = Field(
        default_factory=list,
        description="Explicit allow-list of rule IDs. Empty list means all rules.",
    )
    disabled_rules: list[str] = Field(
        default_factory=list,
        description="Rule IDs to skip regardless of enabled_rules.",
    )
    severity_threshold: str = Field(
        default="low",
        description="Minimum severity to report. One of: critical, high, medium, low, info.",
    )
    output_format: str = Field(
        default="text",
        description="Output format: text, json, or sarif.",
    )
    output_file: Path | None = Field(
        default=None,
        description="Write results to this file instead of stdout.",
    )
    custom_rules_dirs: list[Path] = Field(
        default_factory=list,
        description="Directories containing user-defined rule plugins.",
    )

    @field_validator("severity_threshold")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low", "info"}
        if v.lower() not in allowed:
            raise ValueError(
                f"severity_threshold must be one of {sorted(allowed)}, got {v!r}"
            )
        return v.lower()

    @field_validator("output_format")
    @classmethod
    def _validate_format(cls, v: str) -> str:
        allowed = {"text", "json", "sarif"}
        if v.lower() not in allowed:
            raise ValueError(
                f"output_format must be one of {sorted(allowed)}, got {v!r}"
            )
        return v.lower()


# ---------------------------------------------------------------------------
# Config file discovery
# ---------------------------------------------------------------------------

_CONFIG_FILENAME = ".llm-scanner.yml"


def _find_config_file(start: Path) -> Path | None:
    """Walk up the directory tree from *start* looking for a config file."""
    current = start.resolve()
    while True:
        candidate = current / _CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        parent = current.parent
        if parent == current:
            # Reached filesystem root without finding config.
            return None
        current = parent


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise TypeError(
            f"Config file {path} must contain a YAML mapping, got {type(data).__name__}"
        )
    return data


def _yaml_to_config_dict(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalise YAML keys to ScanConfig field names."""
    mapping: dict[str, Any] = {}

    # Direct field mappings (YAML key → model field).
    direct = {
        "severity_threshold",
        "output_format",
        "output_file",
        "target_path",
    }
    for key in direct:
        if key in raw:
            mapping[key] = raw[key]

    # Aliases used in the example config file.
    if "exclude" in raw:
        mapping["exclude_globs"] = raw["exclude"]
    if "exclude_globs" in raw:
        mapping["exclude_globs"] = raw["exclude_globs"]

    if "disable_rules" in raw:
        mapping["disabled_rules"] = raw["disable_rules"]
    if "disabled_rules" in raw:
        mapping["disabled_rules"] = raw["disabled_rules"]

    if "enable_rules" in raw:
        mapping["enabled_rules"] = raw["enable_rules"]
    if "enabled_rules" in raw:
        mapping["enabled_rules"] = raw["enabled_rules"]

    if "custom_rules_dirs" in raw:
        mapping["custom_rules_dirs"] = raw["custom_rules_dirs"]

    if "rules_dirs" in raw:
        mapping["rules_dirs"] = raw["rules_dirs"]

    return mapping


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config(
    path: Path | None,
    cli_overrides: dict[str, Any] | None = None,
) -> ScanConfig:
    """Load a :class:`ScanConfig`, optionally from *path*, with *cli_overrides*.

    Resolution order (later wins):
    1. Built-in defaults (defined on :class:`ScanConfig`).
    2. Config file discovered by walking up from cwd (or *path* if given).
    3. Explicit *cli_overrides* dict.

    Parameters
    ----------
    path:
        Path to a config file, or ``None`` to auto-discover.
    cli_overrides:
        Dict of field-name → value pairs coming from the CLI layer.  ``None``
        values are ignored so that unset CLI flags don't clobber file config.
    """
    config_dict: dict[str, Any] = {}

    # Resolve config file.
    if path is not None:
        config_file = Path(path).expanduser().resolve()
        if not config_file.is_file():
            raise FileNotFoundError(f"Config file not found: {config_file}")
    else:
        config_file = _find_config_file(Path.cwd())

    if config_file is not None:
        raw = _load_yaml(config_file)
        config_dict.update(_yaml_to_config_dict(raw))

    # Apply CLI overrides (skip None values).
    if cli_overrides:
        for key, value in cli_overrides.items():
            if value is not None:
                config_dict[key] = value

    cfg = ScanConfig(**config_dict)

    extra_excludes = (cli_overrides or {}).get("extra_excludes", [])
    if extra_excludes:
        cfg.exclude_globs = cfg.exclude_globs + list(extra_excludes)

    return cfg
