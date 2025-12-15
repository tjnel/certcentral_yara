"""YARA rule validation module."""

import logging
import subprocess
from enum import Enum
from pathlib import Path

from .models import ValidationResult

logger = logging.getLogger(__name__)


class ValidationEngine(str, Enum):
    """Supported validation engines."""

    YARA = "yara"
    YARA_X = "yara-x"
    BOTH = "both"


def validate_with_yara(rule_path: Path) -> ValidationResult:
    """Validate a YARA rule using yara-python.

    Args:
        rule_path: Path to the YARA rule file.

    Returns:
        ValidationResult with validation status and any errors.
    """
    try:
        import yara

        yara.compile(filepath=str(rule_path))
        logger.debug(f"YARA validation passed: {rule_path}")
        return ValidationResult(
            file_path=str(rule_path),
            is_valid=True,
            engine="yara",
        )
    except ImportError:
        error_msg = "yara-python is not installed"
        logger.error(error_msg)
        return ValidationResult(
            file_path=str(rule_path),
            is_valid=False,
            engine="yara",
            error_message=error_msg,
        )
    except yara.SyntaxError as e:
        error_msg = str(e)
        logger.warning(f"YARA validation failed for {rule_path}: {error_msg}")
        return ValidationResult(
            file_path=str(rule_path),
            is_valid=False,
            engine="yara",
            error_message=error_msg,
        )
    except Exception as e:
        error_msg = str(e)
        logger.error(f"YARA validation error for {rule_path}: {error_msg}")
        return ValidationResult(
            file_path=str(rule_path),
            is_valid=False,
            engine="yara",
            error_message=error_msg,
        )


def validate_with_yara_x(rule_path: Path) -> ValidationResult:
    """Validate a YARA rule using YARA-X CLI.

    Args:
        rule_path: Path to the YARA rule file.

    Returns:
        ValidationResult with validation status and any errors.
    """
    try:
        # Try to use yara-x CLI tool
        result = subprocess.run(
            ["yr", "check", str(rule_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            logger.debug(f"YARA-X validation passed: {rule_path}")
            return ValidationResult(
                file_path=str(rule_path),
                is_valid=True,
                engine="yara-x",
            )
        else:
            error_msg = result.stderr or result.stdout or "Unknown error"
            logger.warning(f"YARA-X validation failed for {rule_path}: {error_msg}")
            return ValidationResult(
                file_path=str(rule_path),
                is_valid=False,
                engine="yara-x",
                error_message=error_msg.strip(),
            )
    except FileNotFoundError:
        error_msg = "YARA-X CLI (yr) is not installed or not in PATH"
        logger.warning(error_msg)
        return ValidationResult(
            file_path=str(rule_path),
            is_valid=False,
            engine="yara-x",
            error_message=error_msg,
        )
    except subprocess.TimeoutExpired:
        error_msg = "YARA-X validation timed out"
        logger.error(f"{error_msg}: {rule_path}")
        return ValidationResult(
            file_path=str(rule_path),
            is_valid=False,
            engine="yara-x",
            error_message=error_msg,
        )
    except Exception as e:
        error_msg = str(e)
        logger.error(f"YARA-X validation error for {rule_path}: {error_msg}")
        return ValidationResult(
            file_path=str(rule_path),
            is_valid=False,
            engine="yara-x",
            error_message=error_msg,
        )


def validate_rule(
    rule_path: Path,
    engine: ValidationEngine = ValidationEngine.YARA,
) -> list[ValidationResult]:
    """Validate a YARA rule with the specified engine(s).

    Args:
        rule_path: Path to the YARA rule file.
        engine: Which validation engine(s) to use.

    Returns:
        List of ValidationResult objects.
    """
    results = []

    if engine in (ValidationEngine.YARA, ValidationEngine.BOTH):
        results.append(validate_with_yara(rule_path))

    if engine in (ValidationEngine.YARA_X, ValidationEngine.BOTH):
        results.append(validate_with_yara_x(rule_path))

    return results


def validate_all_rules(
    rules_dir: Path,
    engine: ValidationEngine = ValidationEngine.YARA,
    pattern: str = "*.yara",
) -> list[ValidationResult]:
    """Validate all YARA rules in a directory.

    Args:
        rules_dir: Directory containing YARA rule files.
        engine: Which validation engine(s) to use.
        pattern: Glob pattern for rule files.

    Returns:
        List of ValidationResult objects for all rules.
    """
    if not rules_dir.exists():
        logger.warning(f"Rules directory does not exist: {rules_dir}")
        return []

    rule_files = sorted(rules_dir.glob(pattern))

    if not rule_files:
        logger.warning(f"No rule files found matching {pattern} in {rules_dir}")
        return []

    all_results = []
    for rule_file in rule_files:
        results = validate_rule(rule_file, engine)
        all_results.extend(results)

    # Log summary
    valid_count = sum(1 for r in all_results if r.is_valid)
    invalid_count = len(all_results) - valid_count

    logger.info(
        f"Validation complete: {valid_count} passed, {invalid_count} failed "
        f"(engine: {engine.value})"
    )

    return all_results


def get_validation_summary(results: list[ValidationResult]) -> dict[str, int]:
    """Get a summary of validation results.

    Args:
        results: List of validation results.

    Returns:
        Dictionary with counts by engine and status.
    """
    summary: dict[str, int] = {
        "total": len(results),
        "valid": 0,
        "invalid": 0,
        "yara_valid": 0,
        "yara_invalid": 0,
        "yara_x_valid": 0,
        "yara_x_invalid": 0,
    }

    for result in results:
        if result.is_valid:
            summary["valid"] += 1
            if result.engine == "yara":
                summary["yara_valid"] += 1
            else:
                summary["yara_x_valid"] += 1
        else:
            summary["invalid"] += 1
            if result.engine == "yara":
                summary["yara_invalid"] += 1
            else:
                summary["yara_x_invalid"] += 1

    return summary


def format_validation_errors(
    results: list[ValidationResult],
    max_errors: int | None = None,
) -> str:
    """Format validation errors for display.

    Args:
        results: List of validation results.
        max_errors: Maximum number of errors to display.

    Returns:
        Formatted string with error details.
    """
    errors = [r for r in results if not r.is_valid]

    if not errors:
        return "No validation errors"

    if max_errors is not None:
        display_errors = errors[:max_errors]
        truncated = len(errors) - max_errors if len(errors) > max_errors else 0
    else:
        display_errors = errors
        truncated = 0

    lines = [f"Found {len(errors)} validation error(s):\n"]

    for error in display_errors:
        lines.append(f"  [{error.engine}] {error.file_path}")
        if error.error_message:
            # Indent error message lines
            for line in error.error_message.split("\n"):
                lines.append(f"    {line}")
        lines.append("")

    if truncated > 0:
        lines.append(f"  ... and {truncated} more errors")

    return "\n".join(lines)

