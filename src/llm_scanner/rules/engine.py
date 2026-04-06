from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from llm_scanner.rules.models import Pattern, Rule

logger = logging.getLogger(__name__)

BUILTIN_RULES_DIR = Path(__file__).parent.parent.parent.parent / "rules" / "builtin"


def _parse_pattern(raw: dict[str, Any]) -> Pattern:
    return Pattern(
        type=raw["type"],
        function=raw.get("function"),
        functions=raw.get("functions", []),
        argument=raw.get("argument"),
        tainted_sources=raw.get("tainted_sources", []),
        sinks=raw.get("sinks", []),
        module=raw.get("module"),
        raw=raw,
    )


def _load_rule_file(path: Path) -> Rule | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not data:
            return None
        patterns = [_parse_pattern(p) for p in data.get("patterns", [])]
        return Rule(
            id=data["id"],
            name=data["name"],
            category=data["category"],
            severity=data["severity"],
            cwe=data.get("cwe", ""),
            languages=data.get("languages", ["python"]),
            patterns=patterns,
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            tags=data.get("tags", []),
        )
    except Exception as e:
        logger.warning(f"Failed to load rule {path}: {e}")
        return None


def load_rules(
    custom_dirs: list[Path] | None = None,
    enabled_rules: list[str] | None = None,
    disabled_rules: list[str] | None = None,
) -> list[Rule]:
    rules: list[Rule] = []
    search_dirs = [BUILTIN_RULES_DIR]
    if custom_dirs:
        search_dirs.extend(custom_dirs)

    for rules_dir in search_dirs:
        if not rules_dir.exists():
            logger.debug(f"Rules directory not found: {rules_dir}")
            continue
        for yaml_file in sorted(rules_dir.rglob("*.yaml")):
            rule = _load_rule_file(yaml_file)
            if rule:
                rules.append(rule)

    # Apply enable/disable filters
    if enabled_rules:
        rules = [r for r in rules if r.id in enabled_rules]
    if disabled_rules:
        disabled_set = set(disabled_rules)
        rules = [r for r in rules if r.id not in disabled_set]

    logger.info(f"Loaded {len(rules)} rules")
    return rules
