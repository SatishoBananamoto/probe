"""Detect plaintext secrets in MCP server configurations."""

import math
import re
from pathlib import Path
from typing import Optional

from ..models import Category, Finding, ServerConfig, Severity

# Known API key / token prefixes
SECRET_PREFIXES = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI/Anthropic API key"),
    (r"sk-ant-[a-zA-Z0-9\-]{20,}", "Anthropic API key"),
    (r"sk-proj-[a-zA-Z0-9]{20,}", "OpenAI project key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub personal access token"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth token"),
    (r"ghs_[a-zA-Z0-9]{36}", "GitHub server token"),
    (r"ghu_[a-zA-Z0-9]{36}", "GitHub user token"),
    (r"github_pat_[a-zA-Z0-9_]{22,}", "GitHub fine-grained PAT"),
    (r"glpat-[a-zA-Z0-9\-]{20,}", "GitLab personal access token"),
    (r"xoxb-[a-zA-Z0-9\-]+", "Slack bot token"),
    (r"xoxp-[a-zA-Z0-9\-]+", "Slack user token"),
    (r"xoxs-[a-zA-Z0-9\-]+", "Slack session token"),
    (r"AKIA[A-Z0-9]{16}", "AWS access key ID"),
    (r"AIza[a-zA-Z0-9\-_]{35}", "Google API key"),
    (r"ya29\.[a-zA-Z0-9_\-]+", "Google OAuth token"),
    (r"[a-f0-9]{32}-us[0-9]+", "Mailchimp API key"),
    (r"sq0atp-[a-zA-Z0-9\-_]{22,}", "Square access token"),
    (r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", "JWT token"),
    (r"npm_[a-zA-Z0-9]{36}", "npm access token"),
    (r"pypi-[a-zA-Z0-9]{60,}", "PyPI API token"),
]

# Keywords that suggest a value is a secret
SECRET_KEY_PATTERNS = [
    r"(?i)api[_\-]?key",
    r"(?i)api[_\-]?secret",
    r"(?i)api[_\-]?token",
    r"(?i)secret[_\-]?key",
    r"(?i)access[_\-]?token",
    r"(?i)auth[_\-]?token",
    r"(?i)bearer[_\-]?token",
    r"(?i)private[_\-]?key",
    r"(?i)password",
    r"(?i)passwd",
    r"(?i)credential",
    r"(?i)client[_\-]?secret",
]

# Values that are obviously NOT secrets (env var references, placeholders)
SAFE_VALUE_PATTERNS = [
    r"^\$\{.+\}$",        # ${ENV_VAR}
    r"^\$[A-Z_]+$",       # $ENV_VAR
    r"^<.+>$",            # <placeholder>
    r"^your[_\-]",        # your_api_key
    r"^xxx+$",            # xxxx
    r"^TODO",             # TODO
    r"^CHANGE[_\-]?ME",   # CHANGEME
    r"^placeholder",      # placeholder
    r"^none$",
    r"^null$",
    r"^true$",
    r"^false$",
    r"^\d+$",             # pure numbers
]


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. High entropy = likely secret."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _is_safe_value(value: str) -> bool:
    """Check if a value is obviously not a secret."""
    for pattern in SAFE_VALUE_PATTERNS:
        if re.match(pattern, value, re.IGNORECASE):
            return True
    return False


def _check_value_for_known_prefix(value: str) -> Optional[str]:
    """Check if value matches a known secret prefix pattern."""
    for pattern, description in SECRET_PREFIXES:
        if re.search(pattern, value):
            return description
    return None


def _mask_secret(value: str, show_chars: int = 4) -> str:
    """Mask a secret value for safe display."""
    if len(value) <= show_chars:
        return "***"
    return value[:show_chars] + "***" + value[-2:]


def scan_config_secrets(server: ServerConfig) -> list[Finding]:
    """Scan a server's config env vars for plaintext secrets."""
    findings = []

    for key, value in server.env.items():
        if not isinstance(value, str) or not value:
            continue

        if _is_safe_value(value):
            continue

        # Check 1: Known secret prefix
        secret_type = _check_value_for_known_prefix(value)
        if secret_type:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=Category.SECRETS,
                title=f"Plaintext {secret_type} in config",
                description=(
                    f"Environment variable '{key}' contains what appears to be "
                    f"a {secret_type} in plaintext. Anyone with read access to "
                    f"this config file can extract this credential."
                ),
                recommendation=(
                    f"Use an environment variable reference instead of hardcoding. "
                    f"Set {key} in your shell profile or use a secret manager like kv-secrets."
                ),
                location=f"{server.source_file}:{server.name}.env.{key}",
                evidence=_mask_secret(value),
            ))
            continue

        # Check 2: Key name suggests secret + high entropy value
        key_is_secret = any(
            re.search(pattern, key) for pattern in SECRET_KEY_PATTERNS
        )
        if key_is_secret and len(value) >= 16:
            entropy = shannon_entropy(value)
            # High entropy (>3.5) on a long string with a secret-like key name
            if entropy > 3.5:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=Category.SECRETS,
                    title=f"Probable plaintext secret in '{key}'",
                    description=(
                        f"Environment variable '{key}' has a secret-like name and "
                        f"contains a high-entropy value (entropy={entropy:.1f}), "
                        f"suggesting it's a hardcoded credential."
                    ),
                    recommendation=(
                        f"Move this value to an environment variable or secret manager. "
                        f"Reference it as ${{{key}}} in your config instead."
                    ),
                    location=f"{server.source_file}:{server.name}.env.{key}",
                    evidence=_mask_secret(value),
                ))
                continue

        # Check 3: Key name suggests secret but value is short/low entropy
        if key_is_secret and len(value) >= 8:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.SECRETS,
                title=f"Possible credential in '{key}'",
                description=(
                    f"Environment variable '{key}' has a secret-like name. "
                    f"Verify this isn't a hardcoded credential."
                ),
                recommendation=(
                    f"If this is a real credential, move it to an environment variable "
                    f"or secret manager."
                ),
                location=f"{server.source_file}:{server.name}.env.{key}",
            ))

    return findings


def scan_source_secrets(server: ServerConfig) -> list[Finding]:
    """Scan server source code for hardcoded secrets."""
    findings = []
    source = server.resolve_server_path()
    if not source:
        return findings

    try:
        content = source.read_text(errors="replace")
    except OSError:
        return findings

    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comments
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Check for known secret prefixes in source code
        for pattern, description in SECRET_PREFIXES:
            match = re.search(pattern, line)
            if match:
                # Make sure it's not in a comment at end of line
                pre_match = line[:match.start()]
                if "#" in pre_match or "//" in pre_match:
                    continue

                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category=Category.SECRETS,
                    title=f"Hardcoded {description} in source",
                    description=(
                        f"Source code contains what appears to be a hardcoded "
                        f"{description}. This will be exposed to anyone with "
                        f"read access to the source file."
                    ),
                    recommendation=(
                        "Move this credential to an environment variable. "
                        "Use os.environ.get() or equivalent to read it at runtime."
                    ),
                    location=f"{source}:{i}",
                    evidence=_mask_secret(match.group(), 6),
                ))

    return findings


def scan(server: ServerConfig) -> list[Finding]:
    """Run all secret scans on a server."""
    findings = []
    findings.extend(scan_config_secrets(server))
    findings.extend(scan_source_secrets(server))
    return findings
